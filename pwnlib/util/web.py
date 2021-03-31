# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division

import os
import six
import tempfile

from pwnlib.log import getLogger
from pwnlib.tubes.buffer import Buffer
from pwnlib.util.misc import size

log = getLogger(__name__)

def wget(url, save=None, timeout=5, **kwargs):
    r"""wget(url, save=None, timeout=5) -> str

    Downloads a file via HTTP/HTTPS.

    Arguments:
      url (str): URL to download
      save (str or bool): Name to save as.  Any truthy value
            will auto-generate a name based on the URL.
      timeout (int): Timeout, in seconds

    Example:

      >>> url    = 'https://httpbin.org/robots.txt'
      >>> result = wget(url, timeout=60)
      >>> result
      b'User-agent: *\nDisallow: /deny\n'

      >>> filename = tempfile.mktemp()
      >>> result2 = wget(url, filename, timeout=60)
      >>> result == open(filename, 'rb').read()
      True
    """
    import requests

    with log.progress("Downloading '%s'" % url, rate=0.1) as w:
        w.status("Making request...")

        response = requests.get(url, stream=True, timeout=timeout, **kwargs)

        if not response.ok:
            w.failure("Got code %s" % response.status_code)
            return

        total_size = int(response.headers.get('content-length',0))

        w.status('0 / %s' % size(total_size))

        # Find out the next largest size we can represent as
        chunk_size = 1
        while chunk_size < (total_size/10):
            chunk_size *= 1000

        # Count chunks as they're received
        buf = Buffer()

        # Loop until we have all of the data
        for chunk in response.iter_content(chunk_size = 2**10):
            buf.add(chunk)
            if total_size:
                w.status('%s / %s' % (size(buf.size), size(total_size)))
            else:
                w.status('%s' % size(buf.size))

        total_data = buf.get()

        # Save to the target file if provided
        if save:
            if not isinstance(save, (bytes, six.text_type)):
                save = os.path.basename(url)
                save = save or tempfile.NamedTemporaryFile(dir='.', delete=False).name
            with open(save,'wb+') as f:
                f.write(total_data)
                w.success('Saved %r (%s)' % (f.name, size(total_data)))
        else:
            w.success('%s' % size(total_data))

        return total_data
