# -*- coding: utf-8 -*-
import os, tempfile
from requests import *
from .. import log

# Using powers of ten instead of two,
# since that's what bandwidth is measured in.
sizes = (
    (10**9, 'gB'),
    (10**6, 'mB'),
    (10**3, 'kB'),
    (1,     'bytes')
)


def wget(url, save=None, timeout=5, **kwargs):
    """wget(url, save=None, timeout=5) -> str

    Downloads a file via HTTP/HTTPS.

    Args:
      url (str): URL to download
      save (str or bool): Name to save as.  Any truthy value
            will auto-generate a name based on the URL.
      timeout (int): Timeout, in seconds

    Example:

      >>> url    = 'http://httpbin.org/robots.txt'
      >>> with context.local(log_level='silent'): result = wget(url)
      >>> result
      'User-agent: *\nDisallow: /deny\n'
      >>> with context.local(log_level='silent'): wget(url, True)
      >>> result == file('robots.txt').read()
      True
    """
    response = get(url, stream=True, **kwargs)

    if not response.ok:
        log.error("Got code %s" % response.status_code)
        return

    log.waitfor("Downloading '%s'" % url)
    total_size = int(response.headers.get('content-length',0))

    # Find out the next largest size we can represent as
    for chunk_size, size_name in sizes:
        if chunk_size < total_size:
            break

    # Count chunks as they're received
    chunks_so_far = 0
    total_chunks  = total_size / chunk_size
    total_data    = ''

    # Loop until we have all of the data
    for chunk in response.iter_content(chunk_size = chunk_size):
        total_data += chunk
        chunks_so_far += 1
        if total_chunks:
            log.status('%s / %s %s' % (chunks_so_far, total_chunks, size_name))
        else:
            log.status('%s %s' % (chunks_so_far, size_name))

    # Save to the target file if provided
    if save:
        if not isinstance(save, (str, unicode)):
            save = os.path.basename(url)
            save = save or NamedTemporaryFile(dir='.', delete=False).name
        with file(save,'wb+') as f:
            f.write(total_data)
            log.done_success('Saved %s %s to %r' % (chunks_so_far, size_name, f.name))
    else:
        log.done_success('%s %s' % (chunks_so_far, size_name))

    return total_data

