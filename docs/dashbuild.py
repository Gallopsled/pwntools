#!/usr/bin/env python

# -*- coding: utf-8 -*-

#
# Helper to build Dash docset from sphinx source files.
#
# Dash docsets can be read by various applications:
#
# Dash         OS X, iOS         https://kapeli.com
# Zeal         Linux, Windows    https://zealdocs.org
# Velocity     Windows           http://velocity.silverlakesoftware.com
# LovelyDocs   Android           http://lovelydocs.io
# dasht        POSIX             https://github.com/sunaku/dasht
# Helm Dash    emacs             https://github.com/areina/helm-dash
#

import argparse
import doc2dash.__main__
import os, os.path
import sphinx
import sqlite3
import sys

sys.path.append(os.path.abspath(os.path.join('..', 'pwnlib')))
import version

def main(args):
	"""Generate a Dash docset from Sphinx source files."""

	srcdir = args.srcdir
	dstdir = args.dstdir
	name = args.name

	if not os.path.exists(dstdir):
		os.makedirs(dstdir)

	# Generate HTML without indices.
	sphinx.build_main([ "sphinx-build", "-b", "html", "-d", os.path.join(dstdir, "doctrees"), \
		"-t", "dash", srcdir, os.path.join(dstdir, "html") ])

	# Convert to docset.
	try:
		doc2dash.__main__.main.main( \
			[ os.path.join(dstdir, "html"), "-d", dstdir, "-n", name, \
					"-f", "-I", "index.html"], "doc2dash", False)
	except SystemExit as e:
		pass

	# Insert a link to the online version.
	online = args.online
	if online is not None and online != "":
		url = online.replace("@VERSION", args.version)
		with open(os.path.join(dstdir, name+".docset", "Contents", "Info.plist"), "r+") as f_info:
			pl = f_info.read()
			pl = pl.replace("</dict>", \
				"\t<key>DashDocSetFallbackURL</key>\n\t<string>%s</string>\n</dict>" % url)
			f_info.seek(0)
			f_info.write(pl)
			f_info.truncate()

	# Modify the CSS to hide the menu included in the HTML.
	with open(os.path.join(dstdir, name+".docset", "Contents", "Resources", "Documents", "_static", "css", "theme.css"), "r+") as f_css:
		css = f_css.read()
		css = css.replace( \
			'@media screen and (max-width: 768px){.wy-body-for-nav{background:#fcfcfc}.wy-nav-top{display:block}',\
			'@media screen {.wy-body-for-nav{background:#fcfcfc}' )
		css = css.replace( \
			'@media screen and (max-width: 480px)', \
			'@media screen ')
		f_css.seek(0)
		f_css.write(css)
		f_css.truncate()

	# Modify the index
	db_conn = sqlite3.connect(os.path.join(dstdir, name+".docset", "Contents", "Resources", "docSet.dsidx"))
	try:
		db_conn.execute('INSERT INTO "searchIndex" ("name","type","path") VALUES ' \
			'("1 Contents", "Guide", "index.html"), ' \
			'("2 About pwntools", "Guide", "about.html"), ' \
			'("3 Installation", "Guide", "install.html"), ' \
			'("4 Getting Started", "Guide", "intro.html"), ' \
			'("5 Globals (pwn)", "Guide", "globals.html"), ' \
			'("6 Command Line Tools", "Guide", "commandline.html")')
		db_conn.execute('DELETE FROM "searchIndex" WHERE "type" = "Module" AND ("name" = "pwn" OR "name" = "pwnlib")')
		db_conn.commit()
	finally:
		db_conn.close()

	return 0

parser = argparse.ArgumentParser()
parser.add_argument("--name", help="docset name", default="pwntools")
parser.add_argument("--online", help="URL for online docs", default="https://pwntools.readthedocs.org/en/@VERSION/")
parser.add_argument("--version", help="pwntools version", default=version.__version__)
parser.add_argument("srcdir", help="Source directory containing .rst files")
parser.add_argument("dstdir", help="Destination and working directory")

main(parser.parse_args())
