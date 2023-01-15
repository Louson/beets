# This file is part of beets.
# Copyright (c) 2011, Jeffrey Aylesworth <mail@jeffrey.red>
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.


from beets.plugins import BeetsPlugin
from beets.ui import Subcommand
from beets import ui
from beets import config
import musicbrainzngs

import re

SUBMISSION_CHUNK_SIZE = 200
FETCH_CHUNK_SIZE = 100
UUID_REGEX = r'^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'


def mb_call(func, *args, **kwargs):
    """Call a MusicBrainz API function and catch exceptions.
    """
    try:
        return func(*args, **kwargs)
    except musicbrainzngs.AuthenticationError:
        raise ui.UserError('authentication with MusicBrainz failed')
    except (musicbrainzngs.ResponseError, musicbrainzngs.NetworkError) as exc:
        raise ui.UserError(f'MusicBrainz API error: {exc}')
    except musicbrainzngs.UsageError:
        raise ui.UserError('MusicBrainz credentials missing')


def submit_albums(collection_id, release_ids):
    """Add all of the release IDs to the indicated collection. Multiple
    requests are made if there are many release IDs to submit.
    """
    for i in range(0, len(release_ids), SUBMISSION_CHUNK_SIZE):
        chunk = release_ids[i:i + SUBMISSION_CHUNK_SIZE]
        mb_call(
            musicbrainzngs.add_releases_to_collection,
            collection_id, chunk
        )


class MusicBrainzCollectionPlugin(BeetsPlugin):
    def __init__(self):
        super().__init__()
        self.oauth = None
        config['musicbrainz']['pass'].redact = True
        config['musicbrainz']['client_secret'].redact = True
        config['musicbrainz']['access_token'].redact = True
        config['musicbrainz']['refresh_token'].redact = True
        if 'user' in config['musicbrainz']:
            musicbrainzngs.auth(
                config['musicbrainz']['user'].as_str(),
                config['musicbrainz']['pass'].as_str(),
            )
        elif 'cliend_id' in config['musicbrainz']:
            musicbrainzngs.oauth(
                config['musicbrainz']['client_id'].as_str(),
                config['musicbrainz']['client_secret'].as_str(),
                )
            self.oauth = musicbrainzngs.OAuth(scope=['collection'])
        else:
            raise ui.UserError('No authentication credential in the configuration')
        self.config.add({
            'auto': False,
            'collection': '',
            'remove': False,
        })
        if self.config['auto']:
            self.import_stages = [self.imported]

    def oauth_setup(self):
        c_key = self.config['musicbrainz']['client_id'].as_str()
        c_secret = self.config['musicbrainz']['client_secret'].as_str()

        # Get the OAuth token from a file or log in.
        if 'access_token' in self.config['musicbrainz']:
            access_token = self.config['musicbrainz']['access_token']
            self.set_token(access_token)
        elif 'refresh_token' in self.config['musicbrainz']:
            refresh_token = self.config['musicbrainz']['access_token']
            refresh_token()
        else:
            raise ui.UserError('No authentication credential. Run command mboauth first.')

    def authenticate(self, c_key, c_secret):
        # Get the link for the OAuth page.
        url = self.oauth.get_authorization_url(code)
        if not url:
            self._log.debug('oauth error: could not create authorize url')
            raise beets.ui.UserError('communication with MusicBrainz failed')

        beets.ui.print_("To authenticate with Beatport, visit:")
        beets.ui.print_(url)

        # Ask for the verifier data and validate it.
        data = beets.ui.input_("Enter the string displayed in your browser:")
        authorization = self.oauth.get_authorization(data)
        if not authorization:
            self._log.debug('oauth error: could not exchange code')
            raise beets.ui.UserError('MusicBrainz token request failed')

        # Save the token for later use.
        token, secret = (authorization['access_token'], authorization['refresh_token'])
        self._log.debug('MusicBrainz token {0}, secret {1}', token, secret)
        self.config.add({
            'access_token': token
            'refresh_token': secret
            })

        return token, secret

    def refresh_token(self):
        """Refresh the access token
        """
        if not 'refresh_token' in config:
            self._log.debug('No refresh token in the configuration')
            raise beets.ui.UserError('authenticate first')
        authorization = self.oauth.refresh_token(self.config['refresh_token'].as_str())
        if not authorization:
            self._log.debug('oauth error: could not exchange code')
            raise beets.ui.UserError('MusicBrainz token request failed')

        # Save the token for later use.
        token = authorization['access_token']
        self._log.debug('MusicBrainz token {0}', token)
        self.config.add({
            'access_token': token
            })

        return access_token

    def revoke_token(self, access=True, refresh=False):
        """Revoke the access token or the refresh token

        :param access:   if unset, do not revoke the access token
        :param refresh:  if set, revoke the refresh token
        """
        if not 'access_token' in config:
            self._log.debug('OAuth2 has not been initialized')
            raise beets.ui.UserError('authenticate first')
        if access:
            self.oauth.revoke_token(self.config['access_token'].as_str())
        if refresh:
            self.oauth.revoke_token(self.config['refresh_token'].as_str())

    def _get_collection(self):
        collections = mb_call(musicbrainzngs.get_collections)
        if not collections['collection-list']:
            raise ui.UserError('no collections exist for user')

        # Get all collection IDs, avoiding event collections
        collection_ids = [x['id'] for x in collections['collection-list']]
        if not collection_ids:
            raise ui.UserError('No collection found.')

        # Check that the collection exists so we can present a nice error
        collection = self.config['collection'].as_str()
        if collection:
            if collection not in collection_ids:
                raise ui.UserError('invalid collection ID: {}'
                                   .format(collection))
            return collection

        # No specified collection. Just return the first collection ID
        return collection_ids[0]

    def _get_albums_in_collection(self, id):
        def _fetch(offset):
            res = mb_call(
                musicbrainzngs.get_releases_in_collection,
                id,
                limit=FETCH_CHUNK_SIZE,
                offset=offset
            )['collection']
            return [x['id'] for x in res['release-list']], res['release-count']

        offset = 0
        albums_in_collection, release_count = _fetch(offset)
        for i in range(0, release_count, FETCH_CHUNK_SIZE):
            albums_in_collection += _fetch(offset)[0]
            offset += FETCH_CHUNK_SIZE

        return albums_in_collection

    def commands(self):
        mbupdate = Subcommand('mbupdate',
                              help='Update MusicBrainz collection')
        mbupdate.parser.add_option('-r', '--remove',
                                   action='store_true',
                                   default=None,
                                   dest='remove',
                                   help='Remove albums not in beets library')
        mbupdate.func = self.update_collection
        mboauth = SubCommand('auth',
                             help='Manage the OAuth2 authentication')
        mboauth.parser.add_option('-r', '--revoke',
                                  default=None,
                                  dest='revoke',
                                  help='Revoke authentication')
        mboauth.func = self.mboauth
        return [mbupdate, mboauth]

    def mboauth(self):
        if self.config['revoke'].get(bool):
            self.revoke(refresh=True)
        else
            self.authenticate()

    def remove_missing(self, collection_id, lib_albums):
        lib_ids = {x.mb_albumid for x in lib_albums}
        albums_in_collection = self._get_albums_in_collection(collection_id)
        remove_me = list(set(albums_in_collection) - lib_ids)
        for i in range(0, len(remove_me), FETCH_CHUNK_SIZE):
            chunk = remove_me[i:i + FETCH_CHUNK_SIZE]
            mb_call(
                musicbrainzngs.remove_releases_from_collection,
                collection_id, chunk
            )

    def update_collection(self, lib, opts, args):
        if 'access_token' in self.config['musicbrainz']:
            self.oauth_setup()
        self.config.set_args(opts)
        remove_missing = self.config['remove'].get(bool)
        self.update_album_list(lib, lib.albums(), remove_missing)

    def imported(self, session, task):
        """Add each imported album to the collection.
        """
        if task.is_album:
            self.update_album_list(session.lib, [task.album])

    def update_album_list(self, lib, album_list, remove_missing=False):
        """Update the MusicBrainz collection from a list of Beets albums
        """
        collection_id = self._get_collection()

        # Get a list of all the album IDs.
        album_ids = []
        for album in album_list:
            aid = album.mb_albumid
            if aid:
                if re.match(UUID_REGEX, aid):
                    album_ids.append(aid)
                else:
                    self._log.info('skipping invalid MBID: {0}', aid)

        # Submit to MusicBrainz.
        self._log.info(
            'Updating MusicBrainz collection {0}...', collection_id
        )
        submit_albums(collection_id, album_ids)
        if remove_missing:
            self.remove_missing(collection_id, lib.albums())
        self._log.info('...MusicBrainz collection updated.')
