// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certloader

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// watcherCoalesceWindow defines the window within which all fsnotify events
// are coalesced together. In other words, the reload happens when
// watcherCoalesceWindow has elapsed since the first file change
const watcherCoalesceWindow = 100 * time.Millisecond

// Watcher is a set of TLS configuration files including CA files, and a
// certificate along with its private key. The files are watched for change and
// reloaded automatically.
type Watcher struct {
	*FileReloader
	log       logrus.FieldLogger
	fswatcher *fsWatcher
	stop      chan struct{}
}

// NewWatcher returns a Watcher that watch over the given file
// paths. The given files are expected to already exists when this function is
// called. On success, the returned Watcher is ready to use.
func NewWatcher(log logrus.FieldLogger, caFiles []string, certFile, privkeyFile string) (*Watcher, error) {
	r, err := NewFileReloaderReady(caFiles, certFile, privkeyFile)
	if err != nil {
		return nil, err
	}
	// An error here would be unexpected as we were able to create a
	// FileReloader having read the files, so the files should exist and be
	// "watchable".
	fswatcher, err := newFsWatcher(caFiles, certFile, privkeyFile)
	if err != nil {
		return nil, err
	}
	w := &Watcher{
		FileReloader: r,
		log:          log,
		fswatcher:    fswatcher,
		stop:         make(chan struct{}),
	}

	w.Watch()
	return w, nil
}

// FutureWatcher returns a channel where exactly one Watcher will be sent once
// the given files are ready and loaded. This can be useful when the file paths
// are well-known, but the files themselves don't exist yet. Note that the
// requirement is that the file directories must exists.
func FutureWatcher(log logrus.FieldLogger, caFiles []string, certFile, privkeyFile string) (<-chan *Watcher, error) {
	r, err := NewFileReloader(caFiles, certFile, privkeyFile)
	if err != nil {
		return nil, err
	}
	fswatcher, err := newFsWatcher(caFiles, certFile, privkeyFile)
	if err != nil {
		return nil, err
	}
	w := &Watcher{
		FileReloader: r,
		log:          log,
		fswatcher:    fswatcher,
		stop:         make(chan struct{}),
	}

	res := make(chan *Watcher)
	go func(res chan<- *Watcher) {
		defer close(res)
		// Attempt a reload without having received any fs notification in case
		// all the files are already there. Note that the keypair and CA are
		// reloaded separately as a "partial update" is still useful: If the
		// FileReloader is "half-ready" (e.g. has loaded the keypair but failed
		// to load the CA), we only need a successfully handled CA related fs
		// notify event to become Ready (in other words, we don't need to
		// receive a fs event for the keypair in that case to become ready).
		_, keypairErr := w.ReloadKeypair()
		_, caErr := w.ReloadCA()
		ready := w.Watch()
		if keypairErr == nil && caErr == nil {
			log.Debug("TLS configuration ready")
			res <- w
			return
		}
		log.Debug("Waiting on fsnotify update to be ready")
		select {
		case <-ready:
			log.Debug("TLS configuration ready")
			res <- w
		case <-w.stop:
		}
	}(res)

	return res, nil
}

// Watch initialize the files watcher and update goroutine. It returns a ready
// channel that will be closed once an update made the underlying FileReloader
// ready.
func (w *Watcher) Watch() <-chan struct{} {
	// prepare the ready channel to be returned. We will close it exactly once.
	var once sync.Once
	ready := make(chan struct{})
	var reload <-chan time.Time

	go func() {
		defer w.fswatcher.Close()
		for {
			select {
			case event := <-w.fswatcher.Events:
				path := event.Name
				w.log.WithFields(logrus.Fields{
					logfields.Path: path,
					"operation":    event.Op,
				}).Debug("Received fsnotify event")

				// Kubernetes implements volume mounts of Secrets and ConfigMaps
				// either by creating a symlink to the certificate/keyfile, or
				// by creating a symlink to a folder containing the files
				// (for projected volume mounts with subpaths). This allows it
				// to update all symlink targets atomically.
				// Unfortunately, this makes also makes it hard to derive which
				// file has been updated, as event.Name alone does not provide
				// enough context. Instead, we would have to to re-resolve
				// the symlinks each time and and update the watched files to
				// contain the new targets w.fswatcher.
				//
				// Instead of doing that, we implement a simpler and hopefully
				// more robust approach of simply watching the volume mount
				// directory (see findKubernetesVolumeMount in newFsWatcher).
				// If there is any update on the volume mount, we coascale all
				// events that we obtain within a certain time window and
				// then reload _all_ certificates and keypairs at once.
				// For regular files, this approach also makes sense in cases
				// where the two files of the key pairs are updated in separate
				// events.
				_, k8sVolumeUpdated := w.fswatcher.k8sVolumes[filepath.Dir(path)]
				_, regularFileUpdated := w.fswatcher.watchedFiles[path]
				if k8sVolumeUpdated || regularFileUpdated {
					// trigger reload of all files
					if reload == nil {
						reload = time.After(watcherCoalesceWindow)
					}
				}
			case <-reload:
				reload = nil // reset reload trigger channel

				if keypair, err := w.ReloadKeypair(); err != nil {
					w.log.WithError(err).Warn("Keypair update failed")
				} else {
					id := keypairId(keypair)
					w.log.WithField("keypair-sn", id).Info("Keypair updated")
				}

				if _, err := w.ReloadCA(); err != nil {
					w.log.WithError(err).Warn("Certificate authority update failed")
				} else {
					w.log.Info("Certificate authority updated")
				}

				if w.Ready() {
					once.Do(func() {
						close(ready)
					})
				}
			case err := <-w.fswatcher.Errors:
				w.log.WithError(err).Warn("fsnotify watcher error")
			case <-w.stop:
				w.log.Info("Stopping fsnotify watcher")
				return
			}
		}
	}()

	return ready
}

// Stop watching the files.
func (w *Watcher) Stop() {
	close(w.stop)
}

// fsWatcher wraps fsnotify.Watcher and contains a list of watched paths
type fsWatcher struct {
	*fsnotify.Watcher
	// watchedFiles contains the file names watched by this watcher
	watchedFiles map[string]struct{}
	// k8sVolumes contains the path to known watched K8s volume mount directories
	k8sVolumes map[string]struct{}
}

// newFsWatcher returns a fsWatcher watching over the given files.
// For each file, we watch it's directory to catch the file creation and deletion
// events. If the file is injected by Kubernetes as part
// of a ConfigMap or Secret volume mount, we watch on the volume mount directory
// instead of the parent directory.
func newFsWatcher(caFiles []string, certFile, privkeyFile string) (*fsWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	fswatcher := &fsWatcher{
		Watcher:      watcher,
		watchedFiles: map[string]struct{}{},
		k8sVolumes:   map[string]struct{}{},
	}

	if err := fswatcher.add(certFile); err != nil {
		watcher.Close()
		return nil, err
	}
	if err := fswatcher.add(privkeyFile); err != nil {
		watcher.Close()
		return nil, err
	}
	for _, path := range caFiles {
		if err := fswatcher.add(path); err != nil {
			watcher.Close()
			return nil, err
		}
	}

	return fswatcher, nil
}

// findKubernetesVolumeMount finds the Kubernetes ConfigMap or Secret volume
// mount path for the given file. It does this by checking each parent folder
// for a '..data' directory.
func findKubernetesVolumeMount(file string) (mount string, ok bool) {
	const k8sData = "..data"
	parent := filepath.Dir(file)
	k8sDataDir := filepath.Join(parent, k8sData)
	if fi, err := os.Stat(k8sDataDir); err == nil && fi.IsDir() {
		return parent, true
	}

	if parent != file {
		if parentMount, ok := findKubernetesVolumeMount(parent); ok {
			return parentMount, true
		}
	}

	return "", false
}

// ad the parent directory of path to the fsnotify.Watcher. If path is part
// of a Kubernetes volume mount, we watch the volume mount instead of the
// parent directory
func (f *fsWatcher) add(path string) error {
	if path == "" {
		return nil
	}

	// We watch the parent directory in order to be able to pick up
	// delete + create sequences
	directory := filepath.Dir(path)

	k8sVolume, isK8sManaged := findKubernetesVolumeMount(path)
	if isK8sManaged {
		// If the file derived from a Kubernetes secret or configmap mount, then
		// we do not want to watch the file itself, as it might be removed and
		// recreated by K8s upon updates. Instead, we want to watch the
		// Kubernetes mount point. See TestKubernetesMount for the expected
		// behavior.
		directory = k8sVolume
	}

	if err := f.Watcher.Add(directory); err != nil {
		return fmt.Errorf("failed to add %q for path %q to fsnotify watcher: %w", directory, path, err)
	}

	f.watchedFiles[path] = struct{}{}
	if isK8sManaged {
		f.k8sVolumes[directory] = struct{}{}
	}

	return nil
}
