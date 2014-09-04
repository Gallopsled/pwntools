# -*- coding: utf-8 -*-
import os, tempfile, urllib2
from .. import log

# Using powers of ten instead of two,
# since that's what bandwidth is measured in.
sizes = (
    (10**9, 'gB'),
    (10**6, 'mB'),
    (10**3, 'kB'),
    (1,     'B')
)


def wget(url, save=None):
    """wget(url, save=None) -> str

    Downloads a file via HTTP/HTTPS.

    Args:
      url (str): URL to download
      save (str or bool): Name to save as.  Any truthy value
            will auto-generate a name based on the URL.

    Example:

      >>> url    = 'http://httpbin.org/robots.txt'
      >>> with context.local(log_level='silent'): result = wget(url)
      >>> result
      'User-agent: *\nDisallow: /deny\n'
      >>> with context.local(log_level='silent'): wget(url, True)
      >>> result == file('robots.txt').read()
      True
    """
    response = urllib2.urlopen(url);

    if response.code != 200:
        log.error("Got code %s" % response.code)
        return

    log.waitfor("Downloading '%s'" % url)
    total_size = response.info().getheader('Content-Length').strip()
    total_size = int(total_size)

    # Find out the next largest size we can represent as
    for chunk_size, size_name in sizes:
        if chunk_size < total_size:
            break

    # Count chunks as they're received
    chunks_so_far = 0
    total_chunks  = total_size / chunk_size
    total_data    = ''

    # Loop until we have all of the data
    chunk = response.read(chunk_size)
    while chunk:
        total_data += chunk
        chunks_so_far += 1
        log.status('%s / %s %s' % (chunks_so_far, total_chunks, size_name))
        chunk = response.read(chunk_size)

    # Check that we got it all before the connection closed
    if len(total_data) != total_size:
        log.done_failure('Did not receive all data')
        return

    # Save to the target file if provided
    if save:
        if not isinstance(save, (str, unicode)):
            save = os.path.basename(url)
            save = save or NamedTemporaryFile(dir='.', delete=False).name
        with file(save,'wb+') as f:
            f.write(total_data)
            log.done_success('Saved data to %r' % f.name)
    else:
        log.done_success()

    return total_data

