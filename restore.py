#!/usr/bin/env python
#
# Author: Sascha Silbe <sascha-pgp@silbe.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""Restore. Activity to write back a Sugar Journal backup in JEB format.
"""

import gettext
import logging
import os
import select
import shutil
import sys
import tempfile
import time
import traceback

if sys.hexversion < 0x02060000:
    # used bundled copy (from Python 2.6) to fix Out-of-Memory issues
    import zipfile26 as zipfile
else:
    import zipfile

import dbus
import gobject
import gtk

try:
    from sugar.activity.widgets import StopButton
    from sugar.graphics.toolbarbox import ToolbarBox
    pre_086_toolbars = False

except ImportError:
    from sugar.graphics.toolbox import Toolbox
    pre_086_toolbars = True

from sugar.activity import activity
import sugar.env
from sugar.graphics.toolbutton import ToolButton
import sugar.logger

try:
    import json
    json.dumps
except (ImportError, AttributeError):
    import simplejson as json


DS_DBUS_SERVICE = "org.laptop.sugar.DataStore"
DS_DBUS_INTERFACE1 = "org.laptop.sugar.DataStore"
DS_DBUS_PATH1 = "/org/laptop/sugar/DataStore"
DS_DBUS_INTERFACE2 = "org.laptop.sugar.DataStore2"
DS_DBUS_PATH2 = "/org/laptop/sugar/DataStore2"
DS_DBUS_SIMPLE_FIND_TIMEOUT = 60
DS_DBUS_SAVE_TIMEOUT = 5*60

CTIME_FORMAT = '%Y-%m-%dT%H:%M:%S'


def format_size(size):
    if not size:
        return _('Empty')
    elif size < 10*1024:
        return _('%4d B') % size
    elif size < 10*1024**2:
        return _('%4d KiB') % (size // 1024)
    elif size < 10*1024**3:
        return _('%4d MiB') % (size // 1024**2)
    else:
        return _('%4d GiB') % (size // 1024**3)


class MalformedBundleException(Exception):
    """Trying to read an invalid bundle."""
    pass


class SaveFailedException(Exception):
    """Saving a data store entry failed."""

    def __init__(self, exception, traceback_string):
        message = _('Failed to save entry to data store')
        Exception.__init__(self, message)
        self.exception = exception
        self.traceback_string = traceback_string


if pre_086_toolbars:
    class StopButton(ToolButton):

        def __init__(self, activity, **kwargs):
            ToolButton.__init__(self, 'activity-stop', **kwargs)
            self.props.tooltip = _('Stop')
            self.props.accelerator = '<Ctrl>Q'
            self.connect('clicked', self.__stop_button_clicked_cb, activity)

        def __stop_button_clicked_cb(self, button, activity):
            activity.close()


class RestoreButton(ToolButton):

    def __init__(self, **kwargs):
        ToolButton.__init__(self, 'journal-import', **kwargs)
        self.props.tooltip = _('Restore Journal').encode('utf-8')
        self.props.accelerator = '<Alt>r'


class AsyncRestore(gobject.GObject):
    """
    Restore a backup to the Sugar data store asynchronously.
    """

    _METADATA_JSON_NAME = '_metadata.json'

    __gsignals__ = {
        'progress': (gobject.SIGNAL_RUN_FIRST, gobject.TYPE_NONE,
            ([int, int])),
        'done': (gobject.SIGNAL_RUN_FIRST, gobject.TYPE_NONE, ([])),
        'error': (gobject.SIGNAL_RUN_FIRST, gobject.TYPE_NONE, ([str])),
    }

    def __init__(self, bundle_path, tmp_dir):
        gobject.GObject.__init__(self)
        self._path = bundle_path
        self._tmp_dir = tmp_dir
        self._bundle = None
        self._child_pid = None
        self._pipe_from_child = None
        self._pipe_to_child = None
        self._pipe_from_child_watch_id = None
        self._data_store = None
        self._data_store_version = None
        self._data_store_mount_id = None

    def start(self):
        """Start the restore process."""
        to_child_read_fd, to_child_write_fd = os.pipe()
        from_child_read_fd, from_child_write_fd = os.pipe()

        self._child_pid = os.fork()
        if not self._child_pid:
            os.close(from_child_read_fd)
            os.close(to_child_write_fd)
            self._pipe_from_child = os.fdopen(from_child_write_fd, 'w')
            self._pipe_to_child = os.fdopen(to_child_read_fd, 'r')
            self._child_run()
            sys.exit(0)
        else:
            os.close(from_child_write_fd)
            os.close(to_child_read_fd)
            self._pipe_from_child = os.fdopen(from_child_read_fd, 'r')
            self._pipe_to_child = os.fdopen(to_child_write_fd, 'w')
            self._pipe_from_child_watch_id = gobject.io_add_watch(
                self._pipe_from_child,
                gobject.IO_IN | gobject.IO_ERR | gobject.IO_HUP,
                self._child_io_cb)

    def abort(self):
        """Abort the restore."""
        self._pipe_to_child.write('abort\n')
        self._parent_close()

    def _child_io_cb(self, source_, condition):
        """Receive and handle message from child."""
        if condition in [gobject.IO_ERR, gobject.IO_HUP]:
            logging.debug('error condition: %r', condition)
            self.emit('error',
                _('Lost connection to child process').encode('utf-8'))
            self._parent_close()
            return False

        status = self._read_line_from_child()
        if status == 'progress':
            position = int(self._read_line_from_child())
            num_entries = int(self._read_line_from_child())
            self.emit('progress', position, num_entries)
            return True

        elif status == 'done':
            self.emit('done')
            self._parent_close()
            return False

        elif status == 'error':
            message = unicode(self._read_line_from_child(), 'utf-8')
            trace = unicode(self._pipe_from_child.read().strip(), 'utf-8')
            logging.error('Child reported error: %s\n%s', message, trace)
            self.emit('error', message.encode('utf-8'))
            self._parent_close()
            return False

        else:
            logging.error('Unknown status %r from child process', status)
            self.emit('error', 'Unknown status %r from child process', status)
            self.abort()
            return False

    def _read_line_from_child(self):
        """Read a line from the child process using low-level IO.

        This is a hack to work around the fact that file.readline() buffers
        data without us knowing about it. If we call readline() a second
        time when no data is buffered, it may block (=> the UI would hang).
        If OTOH there is another line already in the buffer, we won't get
        notified about it by select() as it already is in userspace.
        There are cleaner ways to handle this (e.g. using the asyncore module),
        but they are much more complex.
        """
        line = []
        while True:
            character = os.read(self._pipe_from_child.fileno(), 1)
            if character == '\n':
                return ''.join(line)

            line.append(character)

    def _parent_close(self):
        """Close connections to child and wait for it."""
        gobject.source_remove(self._pipe_from_child_watch_id)
        self._pipe_from_child.close()
        self._pipe_to_child.close()
        pid_, status = os.waitpid(self._child_pid, 0)
        if os.WIFEXITED(status):
            logging.debug('Child exited with rc=%d', os.WEXITSTATUS(status))
        elif os.WIFSIGNALED(status):
            logging.debug('Child killed by signal %d', os.WTERMSIG(status))
        else:
            logging.error('Sudden infant death syndrome')

    def _child_run(self):
        """Main program of child."""
        try:
            self._connect_to_data_store()
            self._bundle = zipfile.ZipFile(self._path, 'r')
            self._check_bundle()

            entries = self._get_directories()
            num_entries = len(entries)
            for position, (object_id, file_paths) in enumerate(entries):
                self._client_check_command()

                if len(object_id) < 36:
                    logging.warning('Ignoring unknown directory %r', object_id)
                    continue

                if self._METADATA_JSON_NAME not in file_paths:
                    logging.warning('Ignoring directory %r without %s',
                        object_id, self._METADATA_JSON_NAME)
                    continue

                logging.debug('processing entry %r', object_id)

                self._install_entry(object_id, file_paths)

                self._send_to_parent('progress\n%d\n%d\n' % (position,
                    num_entries))

            self._send_to_parent('progress\n%d\n%d\n' % (num_entries,
                num_entries))
            self._close_bundle()
            self._send_to_parent('done\n')

        # pylint: disable=W0703
        except Exception, exception:
            self._pipe_from_child.write('error\n')
            message = unicode(exception).encode('utf-8')
            self._pipe_from_child.write(message+'\n')
            trace = unicode(traceback.format_exc()).encode('utf-8')
            if hasattr(exception, 'traceback_string'):
                trace += unicode(exception.traceback_string).encode('utf-8')
            self._pipe_from_child.write(trace)
            self._close_bundle()
            sys.exit(2)

    def _send_to_parent(self, message):
        self._pipe_from_child.write(message)
        self._pipe_from_child.flush()

    def _client_check_command(self):
        """Check for and execute command from the parent."""
        in_ready, out_ready_, errors_on_ = select.select([self._pipe_to_child],
            [], [], 0)
        if not in_ready:
            return

        command = self._pipe_to_child.readline().strip()
        logging.debug('command %r received', command)
        if command == 'abort':
            self._remove_bundle()
            sys.exit(1)
        else:
            raise ValueError('Unknown command %r' % (command, ))

    def _check_bundle(self):
        """Check bundle for validity."""
        # potentially expensive, but avoids trouble during unpacking
        if self._bundle.testzip() is not None:
            raise MalformedBundleException(_('Corrupt zip file'))

        file_names = self._bundle.namelist()
        if not file_names:
            raise MalformedBundleException(_('Empty bundle'))

        metadata_seen = False
        for name in file_names:
            for part in name.split('/'):
                if part.startswith('.'):
                    raise MalformedBundleException(
                        _('Path component starts with dot: %r') % (name, ))

            if name.split('/')[-1] == self._METADATA_JSON_NAME:
                metadata_seen = True

        if not metadata_seen:
            raise MalformedBundleException('No metadata file found')

    def _read_data(self, object_id):
        """Read data for given object from bundle."""
        data_fd, data_file_name = tempfile.mkstemp(prefix='Restore',
            dir=self._tmp_dir)
        data_file = os.fdopen(data_fd, 'w')
        os.chmod(data_file_name, 0644)
        try:
            # TODO: predict disk-full
            in_file = self._bundle.open(os.path.join(object_id, object_id))
            try:
                shutil.copyfileobj(in_file, data_file)
            finally:
                in_file.close()
            return data_file_name
        finally:
            data_file.close()

    def _read_metadata(self, object_id):
        """Read metadata for given object from bundle."""
        metadata_path = os.path.join(object_id, self._METADATA_JSON_NAME)
        json_data = self._bundle.read(metadata_path)
        return json.loads(json_data)

    def _get_directories(self):
        """Get the names of top-level directories in bundle and of their files.
        """
        contents = {}
        order = []
        for path in self._bundle.namelist():
            if path.endswith('/'):
                continue

            directory, file_name = path.lstrip('/').split('/', 1)
            if directory not in contents:
                order.append(directory)
            contents.setdefault(directory, []).append(file_name)

        return [(directory, contents[directory]) for directory in order]

    def _install_entry(self, object_id, file_paths):
        """Reassemble the given entry and save it to the data store.

        file_paths is destroyed as a side effect."""
        file_paths.remove(self._METADATA_JSON_NAME)
        metadata = self._read_metadata(object_id)

        data_file_name = ''
        if object_id in file_paths:
            file_paths.remove(object_id)
            data_file_name = self._read_data(object_id)

        for path in file_paths:
            components = path.split('/')
            if len(components) != 2 or components[1] != object_id:
                logging.warning('Ignoring unknown file %r', path)

            name = components[0]
            value = self._bundle.read(os.path.join(object_id, path))
            metadata[name] = dbus.ByteArray(value)

        del file_paths[:]
        try:
            self._save_entry(metadata, data_file_name)
        except Exception, exception:
            logging.exception('_save_entry(%r, %r) failed', metadata,
                data_file_name)
            raise SaveFailedException(exception, traceback.format_exc())

    def _close_bundle(self):
        """Ensure the bundle is closed."""
        if self._bundle and self._bundle.fp and not self._bundle.fp.closed:
            self._bundle.close()

    def _connect_to_data_store(self):
        """Open a connection to a Sugar data store."""
        # We forked => need to use a private connection and make sure we
        # never allow the main loop to run
        # http://lists.freedesktop.org/archives/dbus/2007-April/007498.html
        # http://lists.freedesktop.org/archives/dbus/2007-August/008359.html
        bus = dbus.SessionBus(private=True)
        try:
            self._data_store = dbus.Interface(bus.get_object(DS_DBUS_SERVICE,
                DS_DBUS_PATH2), DS_DBUS_INTERFACE2)
            self._data_store.find({'tree_id': 'invalid'},
                {'metadata': ['tree_id']}, timeout=DS_DBUS_SIMPLE_FIND_TIMEOUT)
            self._data_store_version = 1000
            logging.info('Data store with version support found')
            return

        except dbus.DBusException:
            logging.debug('No data store with version support found')

        self._data_store = dbus.Interface(bus.get_object(DS_DBUS_SERVICE,
            DS_DBUS_PATH1), DS_DBUS_INTERFACE1)
        self._data_store.find({'uid': 'invalid'}, ['uid'],
            timeout=DS_DBUS_SIMPLE_FIND_TIMEOUT)
        if 'uri' in self._data_store.mounts()[0]:
            self._data_store_version = 82
            data_store_path = '/home/olpc/.sugar/default/datastore'
            self._data_store_mount_id = [mount['id']
                for mount in self._data_store.mounts()
                if mount['uri'] == data_store_path][0]
            logging.info('0.82 data store found')
        else:
            logging.info('0.84+ data store without version support found')
            self._data_store_version = 84

    def _get_timestamp(self, metadata):
        if 'timestamp' in metadata:
            return float(metadata['timestamp'])
        elif 'mtime' in metadata:
            return time.mktime(time.strptime(metadata['mtime'], CTIME_FORMAT))
        elif 'ctime' in metadata:
            return time.mktime(time.strptime(metadata['ctime'], CTIME_FORMAT))

        logging.warning('Entry without any kind of timestamp: %r', metadata)
        return 0

    def _save_entry(self, metadata, data_path):
        """Store object in data store."""
        timestamp = self._get_timestamp(metadata)
        # workaround for SL#1590
        metadata['timestamp'] = str(int(timestamp))

        if self._data_store.dbus_interface == DS_DBUS_INTERFACE2:
            tree_id = metadata.get('tree_id') or metadata['uid']
            version_id = metadata.get('version_id', '')
            parent_id = metadata.get('parent_id', '')
            if self._find_entry_v2(tree_id, version_id):
                logging.info('Skipping existing entry %r / %r', tree_id,
                    version_id)
                return

            self._data_store.save(tree_id, parent_id, metadata, data_path,
                True, timeout=DS_DBUS_SAVE_TIMEOUT)
        else:
            uid = metadata.get('uid') or metadata['tree_id']
            entry = self._find_entry_v1(uid)
            if entry:
                ds_timestamp = self._get_timestamp(entry)

                if ds_timestamp >= int(timestamp):
                    logging.info('Skipping outdated entry for %r', uid)
                    return
                else:
                    logging.info('Overwriting older entry for %r', uid)
            else:
                logging.info('Restoring entry %r', uid)

            if self._data_store_version == 82:
                metadata['uid'] = uid
                metadata.pop('mountpoint', None)
                metadata['mtime'] = time.strftime(CTIME_FORMAT, time.localtime(timestamp))

            if self._data_store_version == 82 and not entry:
                self._data_store.create(metadata, data_path, True,
                    timeout=DS_DBUS_SAVE_TIMEOUT)
            else:
                self._data_store.update(uid, metadata, data_path, True,
                    timeout=DS_DBUS_SAVE_TIMEOUT)

    def _find_entry_v1(self, uid):
        """Retrieve given entry from v1 data store if it exists.
        """
        try:
            entry = self._data_store.get_properties(uid, byte_arrays=True,
                timeout=DS_DBUS_SIMPLE_FIND_TIMEOUT)

        except dbus.DBusException, exception:
            exception_name = exception.get_dbus_name()
            if exception_name.startswith('org.freedesktop.DBus.Python'):
                return None

            raise

        if self._data_store_version == 82 and \
                entry['mountpoint'] != self._data_store_mount_id:
            return None

        return entry

    def _find_entry_v2(self, tree_id, version_id):
        """Retrieve given entry from v2 data store if it exists.
        """
        query = {'tree_id': tree_id}
        if version_id:
            query['version_id'] = version_id

        entries = self._data_store.find(query, {}, byte_arrays=True,
            timeout=DS_DBUS_SIMPLE_FIND_TIMEOUT)[0]
        if entries:
            return entries[0]
        return None


class RestoreActivity(activity.Activity):

    def __init__(self, handle):
        activity.Activity.__init__(self, handle, create_jobject=False)
        self.max_participants = 1
        self._progress_bar = None
        self._message_box = None
        self._restore = None
        self._restore_button = None
        self._no_bundle_warning = None
        self._path = None
        self._setup_widgets()

    def read_file(self, file_path):
        """Set path to bundle to restore."""
        self._path = file_path
        self._no_bundle_warning.hide()
        self._restore_button.set_sensitive(True)

    def write_file(self, file_path):
        """We don't have any state to save in the Journal."""
        return

    def save(self):
        """We don't have any state to save in the Journal."""
        return

    def close(self, skip_save=False):
        """We don't have any state to save in the Journal."""
        activity.Activity.close(self, skip_save=True)

    def _setup_widgets(self):
        self._setup_toolbar()
        self._setup_main_view()

    def _setup_main_view(self):
        vbox = gtk.VBox()
        warning = _('No bundle selected. Please close this activity and'
            ' choose a bundle to restore from the Journal.')
        self._no_bundle_warning = gtk.Label(warning.encode('utf-8'))
        vbox.pack_start(self._no_bundle_warning, True)
        self.set_canvas(vbox)
        vbox.show_all()

    def _setup_toolbar(self):
        if pre_086_toolbars:
            self.toolbox = Toolbox()
            self.set_toolbox(self.toolbox)

            toolbar = gtk.Toolbar()
            self.toolbox.add_toolbar('Toolbar', toolbar)
            toolbar_box = self.toolbox

        else:
            toolbar_box = ToolbarBox()
            toolbar = toolbar_box.toolbar
            self.set_toolbar_box(toolbar_box)

        self._restore_button = RestoreButton()
        self._restore_button.connect('clicked', self._restore_cb)
        self._restore_button.set_sensitive(False)
        toolbar.insert(self._restore_button, -1)

        separator = gtk.SeparatorToolItem()
        separator.props.draw = False
        separator.set_expand(True)
        toolbar.insert(separator, -1)

        stop_button = StopButton(self)
        toolbar.insert(stop_button, -1)

        toolbar_box.show_all()

    def _restore_cb(self, button):
        """Callback for Restore button."""
        self._setup_restore_view()
        self._start_restore()

    def _start_restore(self):
        """Set up and start background worker process."""
        base_dir = os.environ.get('SUGAR_ACTIVITY_ROOT')
        if not base_dir:
            base_dir = sugar.env.get_profile_path(self.get_bundle_id())

        tmp_dir = os.path.join(base_dir, 'instance')
        self._restore = AsyncRestore(self._path, tmp_dir)
        self._restore.connect('progress', self._progress_cb)
        self._restore.connect('error', self._error_cb)
        self._restore.connect('done', self._done_cb)
        self._restore.start()

    def _setup_restore_view(self):
        """Set up UI for showing feedback from worker process."""
        self._restore_button.set_sensitive(False)
        vbox = gtk.VBox(False)

        label_text = _('Restoring Journal from %s') % (self._path, )
        label = gtk.Label(label_text.encode('utf-8'))
        label.show()
        vbox.pack_start(label)

        alignment = gtk.Alignment(xalign=0.5, yalign=0.5, xscale=0.5)
        alignment.show()

        self._progress_bar = gtk.ProgressBar()
        self._progress_bar.props.text = _('Scanning bundle').encode('utf-8')
        self._progress_bar.show()
        alignment.add(self._progress_bar)
        vbox.add(alignment)

        self._message_box = gtk.Label()
        vbox.pack_start(self._message_box)

        # FIXME
#        self._close_button = gtk.Button(_('Abort'))
#        self._close_button.connect('clicked', self._close_cb)
#        self._close_button.show()
#        button_box = gtk.HButtonBox()
#        button_box.show()
#        button_box.add(self._close_button)
#        vbox.pack_start(button_box, False)

        vbox.show()
        self.set_canvas(vbox)
        self.show()

    def _progress_cb(self, restore_, position, num_entries):
        """Update progress bar with information from child process."""
        self._progress_bar.props.text = '%d / %d' % (position, num_entries)
        self._progress_bar.props.fraction = float(position) / num_entries

    def _done_cb(self, restore_):
        """Restore finished."""
        logging.debug('_done_cb')
        self._restore_button.set_sensitive(True)
#        self._close_button.set_label(_('Finish'))

    def _error_cb(self, restore_, message):
        """Receive error message from child process."""
        self._show_error(unicode(message, 'utf-8'))
        self._restore_button.set_sensitive(True)

    def _show_error(self, message):
        """Present error message to user."""
        self._message_box.props.label = unicode(message).encode('utf-8')
        self._message_box.show()

#    def _close_cb(self, button):
#        if not self._done:
#            self._restore.abort()

#        self.emit('close')


# pylint isn't smart enough for the gettext.install() magic
_ = lambda msg: msg
gettext.install('restore', 'po', unicode=True)
sugar.logger.start()
