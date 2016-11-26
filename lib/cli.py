#!/usr/bin/env python3

# Copyright © 2016 Jakub Wilk <jwilk@jwilk.net>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the “Software”), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import asyncio
import http
import io
import json
import os
import re
import subprocess
import sys
import urllib.parse

import aiohttp
import tqdm
import uritemplate

user_agent = 'github-upload (https://github.com/jwilk/github-upload)'
api_endpoint = 'https://api.github.com'

class GitHubError(RuntimeError):

    def __init__(self, status, reason, body):
        super().__init__(self)
        msg = '{status} {reason}\n\n{body}'.format(
            status=status,
            reason=reason,
            body=json.dumps(body, sort_keys=True, indent=4, separators=(',', ': '))
        )
        self.args = (msg,)
        self.status = status

async def json_request(method, url, headers={}, **kwargs):
    if json_request.debug:
        print('*', method.__name__.upper(), url, file=sys.stderr)
    url = urllib.parse.urljoin(api_endpoint, url)
    headers = dict(headers,
        Accept='application/vnd.github.v3+json'
    )
    response = await method(url, headers=headers, **kwargs)
    if response.status == http.HTTPStatus.NO_CONTENT:
        response.close()
        return
    body = await response.json()
    if response.status in {http.HTTPStatus.OK, http.HTTPStatus.CREATED}:
        pass
    else:
        raise GitHubError(response.status, response.reason, body)
    return body
json_request.debug = False

@asyncio.coroutine
def file_reader(file, chunk_size=4096, callback=int):
    while True:
        chunk = file.read(chunk_size)
        if chunk:
            yield chunk
            callback(len(chunk))
        else:
            return

async def amain(options):
    token = os.environ['GITHUB_TOKEN']
    headers = {
        'User-Agent': user_agent,
        'Authorization': ('token ' + token),
    }
    async with aiohttp.ClientSession(headers=headers) as session:
        url = '/repos/{repo}/git/refs/tags/{tag}'.format(repo=options.repo, tag=options.tag)
        taginfo = await json_request(session.get, url)
        url = '/repos/{repo}/releases/tags/{tag}'.format(repo=options.repo, tag=options.tag)
        try:
            relinfo = await json_request(session.get, url)
        except GitHubError as exc:
            if exc.status == http.HTTPStatus.NOT_FOUND:
                relinfo = {}
        if not relinfo:
            data = dict(
                tag_name=options.tag,
                target_commitish=taginfo['object']['sha']
            )
            data = json.dumps(data)
            url = '/repos/{repo}/releases'.format(repo=options.repo)
            relinfo = await json_request(session.post, url, data=data)
        if options.delete_all:
            url = relinfo['url']
            await json_request(session.delete, url)
        upload_url_template = relinfo['upload_url']
        assets = {}
        for asset in relinfo['assets']:
            name = asset['name']
            assets[name] = asset
        for path in options.files:
            name = os.path.basename(path)
            try:
                asset = assets[name]
            except KeyError:
                if options.delete:
                    raise
            else:
                if options.overwrite or options.delete:
                    url = asset['url']
                    await json_request(session.delete, url)
                    print('{url} deleted'.format(url=asset['browser_download_url']))
                else:
                    url = asset['browser_download_url']
                    print('{url} already exists; maybe try --overwrite?'.format(url=url), file=sys.stderr)
                    sys.exit(1)
            if options.delete:
                continue
            url = uritemplate.expand(upload_url_template, dict(name=name))
            with open(path, 'rb') as file:
                file.seek(0, io.SEEK_END)
                size = file.tell()
                file.seek(0)
                headers = {
                    'Content-Length': str(size),
                    'Content-Type': 'application/octet-stream',
                }
                with tqdm.tqdm(unit='B', unit_scale=True, leave=True) as progress:
                    progress.desc = '{path} '.format(path=path)
                    progress.total = size
                    progress.refresh()
                    reader = file_reader(file, callback=progress.update)
                    fileinfo = await json_request(
                        session.post,
                        url,
                        headers=headers,
                        data=reader,
                    )
                    progress.desc = '{url} '.format(url=fileinfo['browser_download_url'])
                    progress.refresh()

def ap_repository(repo):
    if re.match(r'\A[^/\s]+/[^/\s]+\Z', repo):
        return repo
    else:
        raise ValueError
ap_repository.__name__ = 'repository'

def ap_tag(tag):
    if re.match(r'\A[^/\s]+\Z', tag):
        return tag
    else:
        raise ValueError
ap_tag.__name__ = 'tag'

class GitRemoteError(Exception):
    pass

def guess_github_repo():
    cmdline = 'git remote get-url origin'
    cproc = subprocess.run(
        cmdline.split(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    if cproc.returncode != 0:
        raise GitRemoteError(
            '"{cmdline}" failed:\n{msg}'.format(
                cmdline=cmdline,
                msg=cproc.stderr.strip()
            )
        )
    url = cproc.stdout.rstrip()
    (scheme, netloc, path, query, fragment) = urllib.parse.urlsplit(url)
    if netloc == 'github.com':
        if path.endswith('.git'):
            path = path[:-4]
        return path.lstrip('/')
    else:
        raise GitRemoteError(
            'cannot parse git URL {url!r}'.format(url=url)
        )

def main():
    ap = argparse.ArgumentParser()
    gr = ap.add_mutually_exclusive_group(required=True)
    gr.add_argument('-r', '--repository', type=ap_repository)
    gr.add_argument('-R', '--git-remote', action='store_true')
    ap.add_argument('-t', '--tag', type=ap_tag, required=True)
    ap.add_argument('--overwrite', action='store_true', help='overwrite existing files')
    ap.add_argument('--delete', action='store_true', help='delete files')
    ap.add_argument('--delete-all', action='store_true', help='delete the whole release')
    ap.add_argument('--debug', action='store_true')
    ap.add_argument('files', metavar='FILE', nargs='*', help='files to upload')
    options = ap.parse_args()
    options.repo = options.repository
    del options.repository
    if options.git_remote:
        try:
            options.repo = guess_github_repo()
        except GitRemoteError as exc:
            ap.error(exc)
    assert options.repo is not None
    if options.delete_all:
        if len(options.files) > 0:
            ap.error('too many arguments')
    else:
        if len(options.files) == 0:
            ap.error('not enough arguments')
    if not options.delete:
        for path in options.files:
            try:
                with open(path, 'rb') as file:
                    file.seek(0, io.SEEK_END)
                    size = file.tell()
                    if size == 0:
                        ap.error('{path}: cannot upload empty files'.format(path=path))
            except IOError as exc:
                ap.error('{path}: {exc}'.format(path=path, exc=exc))
    if options.debug:
        json_request.debug = True
    loop = asyncio.get_event_loop()
    loop.run_until_complete(amain(options))
    loop.close()

if __name__ == '__main__':
    main()

# vim:ts=4 sts=4 sw=4 et