Memory Pool System Release Build Procedure
==========================================
:author: Richard Brooksby
:organization: Ravenbrook Limited
:date: 2002-06-17
:revision: $Id$
:confidentiality: public
:copyright: See `C. Copyright and License`_


1. Introduction
---------------

This is the procedure for building a generic release of the Memory Pool
System (an “MPS Kit”) from the version sources.

The intended readership of this document is Ravenbrook development
staff. (If you are a user of the MPS, and want to build object code from
an MPS Kit, please see the ``readme.txt`` file in the kit.)

This document is not confidential.

All relative paths are relative to
``//info.ravenbrook.com/project/mps/``.


2. Prerequisites
----------------

#. Make sure you have a version branch from which to make the release.
   If not, follow the `version creation procedure`_ first.

   .. _version creation procedure: version-create

#. Make sure that you can authenticate to Git Fusion, and that you
   have rights to push to the ``mps`` repository on GitHub. If not,
   follow the `Git Fusion procedures`_ first.

   .. _Git Fusion procedures: https://info.ravenbrook.com/procedure/git-fusion


3. Setting up for release
-------------------------

#. Choose a *RELEASE* name of the form *VERSION.N* (for example,
   1.111.0), where *VERSION* is the number of the version you’re
   releasing, and *N* is the first unused release number (starting at
   zero). Look in the index of releases (``release/index.html``) for
   existing release numbers for your version. ::

        VERSION=A.BBB
        RELEASE=$VERSION.N

#. Check that the macro ``MPS_RELEASE`` in ``code/version.c`` has the
   correct value.

#. Check that ``readme.txt`` contains an up-to-date description of the
   release you intend to build. For example, is the list of supported
   platforms still correct?

#. Check that ``manual/source/release.rst`` contains a section with an
   up-to-date description of significant user-visible changes since
   the previous release.

#. Determine the *CHANGELEVEL* at which you’re going to make the
   release. This will usually be the latest submitted changelevel on
   the branch from which you are making the release; to get it, use
   ``p4 changes -m 1``::

        CHANGELEVEL=$(p4 changes -m 1 ... | cut -d' ' -f2)


4. Pre-release testing
----------------------

#. Sync the version sources to precisely the *CHANGELEVEL* you
   determined above, with no extraneous files, by using the following
   procedure::

        p4 opened version/$VERSION/...

   This should output "version/$VERSION/... - file(s) not opened on
   this client." But if there are opened files, then::

        p4 revert version/$VERSION/...

   Next::

	p4 update version/$VERSION/...@$CHANGELEVEL
	p4 status version/$VERSION/...

   This should output "version/$VERSION/... - no file(s) to
   reconcile." But if there are discrepancies, then::

        rm -rf version/$VERSION
        p4 sync -f version/$VERSION/...@$CHANGELEVEL

   See [RHSK_2008-10-16]_.

#. Run the test suite::

        (cd version/$VERSION && ./configure && make test)

   Check that the test suite passes.

#. Repeat for all supported platforms. On Windows the sequence of
   commands to run the test suite are::

        cd version\$VERSION\code
        nmake /f w3i6mv.nmk clean testci
        nmake /f ananmv.nmk clean testansi
        nmake /f ananmv.nmk CFLAGS="-DCONFIG_POLL_NONE" clean testpollnone
        cd ../test
        perl test/qa runset testsets/{coolonly,argerr,conerr,passing}

#. Check that there are no performance regressions by comparing the
   benchmarks (``djbench`` and ``gcbench``) for the last release and
   this one.


5. Making the release (automated procedure)
-------------------------------------------

Run the script ``tool/release``, passing the options:

* ``-P mps`` — project name
* ``-b BRANCH`` — branch to make the release from: for example ``version/1.113``
* ``-C CHANGELEVEL`` — changelevel at which to make the release
* ``-d "DESCRIPTION"`` — description of the release
* ``-y`` — yes, really make the release

If omitted, the project and branch are deduced from the current
directory, and the changelevel defaults to the most recent change on
the branch. A typical invocation looks like this::

    tool/release -b version/$VERSION -d "Improved interface to generation chains." -y


6. Making the release (manual procedure)
----------------------------------------

.. note::

   If you are creating a customer-specific variant then vary the
   release name according to the variant, for example,
   ``mps-cet-1.110.0.zip``

On a Unix (including macOS) machine:

#. Create a fresh Perforce client workspace::

        CLIENT=mps-release-$RELEASE
        p4 client -i <<END
        Client: $CLIENT
        Root: /tmp/$CLIENT
        Description: Temporary client for making MPS Kit release $RELEASE
        LineEnd: local
        View:
                //info.ravenbrook.com/project/mps/version/$VERSION/... //$CLIENT/mps-kit-$RELEASE/...
                //info.ravenbrook.com/project/mps/release/$RELEASE/... //$CLIENT/release/$RELEASE/...
        END

#. Sync this client to *CHANGELEVEL*::

        p4 -c $CLIENT sync -f @$CHANGELEVEL

#. Create a tarball containing the MPS sources, and open it for add::

        pushd /tmp/$CLIENT
        mkdir -p release/$RELEASE
        tar czf release/$RELEASE/mps-kit-$RELEASE.tar.gz mps-kit-$RELEASE
        popd
        p4 -c $CLIENT add /tmp/$CLIENT/release/$RELEASE/mps-kit-$RELEASE.tar.gz

#. Switch the Perforce client workspace to Windows (CRLF) line
   endings::

        p4 -c $CLIENT client -o | sed "s/^LineEnd:.local/LineEnd: win/" | p4 client -i

#. Sync the version sources again::

        rm -rf /tmp/$CLIENT/version/$VERSION
        p4 -c $CLIENT sync -f @$CHANGELEVEL

#. Create a zip file containing the MPS sources, and open it for add::

        pushd /tmp/$CLIENT
        mkdir -p release/$RELEASE
        zip -r release/$RELEASE/mps-kit-$RELEASE.zip mps-kit-$RELEASE
        popd
        p4 -c $CLIENT add /tmp/$CLIENT/release/$RELEASE/mps-kit-$RELEASE.zip

#. Submit the release files to Perforce::

        p4 -c $CLIENT submit -d "MPS: adding the MPS Kit tarball and zip file for release $RELEASE."

#. Delete the temporary Perforce client::

        p4 -c $CLIENT client -d $CLIENT
        rm -rf /tmp/$CLIENT

#. Edit the index of releases (``release/index.html``) and add the
   release to the table, in a manner consistent with previous releases.

#. Edit the index of versions (``version/index.html``) and add the
   release to the list of releases for *VERSION*, in a manner consistent
   with previous releases.

#. Edit the main MPS Project index page (``index.rst``), updating the
   "Download the latest release" link.

#. Submit these changes to Perforce::

        p4 submit -d "MPS: registered release $RELEASE."


7. Registering the release
--------------------------

#. Visit the `project
   updater <https://info.ravenbrook.com/infosys/cgi/data_update.cgi>`__,
   select “mps” from the dropdown, and hit “Find releases”.

#. Make a git tag for the release::

        git clone ssh://git@perforce.ravenbrook.com:1622/mps-public
        cd mps-public
        git checkout -b version/$VERSION origin/version/$VERSION
        git tag -a release-$RELEASE -F - <<END
        Memory Pool System Kit release $RELEASE.
        See <https://www.ravenbrook.com/project/mps/release/>.
        END
        git push --tags git@github.com:Ravenbrook/mps.git

#. Go to the `list of releases on Github
   <https://github.com/Ravenbrook/mps/releases>`__ and
   select "Draft a new release". Select the tag you just pushed, and
   set the title and description to match the other releases.

#. Inform the project manager and staff by e-mail to
   mps-staff@ravenbrook.com.

#. Announce the new release by e-mail to
   mps-discussion@ravenbrook.com. Include a summary of the release
   notes.


A. References
-------------

.. [RHSK_2008-10-16] Richard Kistruck; "revert ; rm ; sync -f";
   Ravenbrook Limited; 2008-10-16;
   <https://info.ravenbrook.com/mail/2008/10/16/13-08-20/0.txt>.


B. Document History
-------------------

==========  =====  ==========================================================
2002-06-17  RB_    Created based on P4DTI procedure.
2002-06-19  NB_    Fixed up based on experience of release 1.100.0.
2004-03-03  RB_    Fixed the way we determine the release changelevel to avoid possible pending changelists.
2005-10-06  RHSK_  Clarify this procedure is for general MPS Kit releases; correct ``cp -r`` to ``-R``. Add: check ``version.c``.
2006-01-19  RHSK_  Correct readership statement, and direct MPS users to the mps-kit readme.
2006-02-16  RHSK_  Use Info-ZIP (free) for Windows archives, not WinZip.
2007-07-05  RHSK_  Releasename now also in ``w3build.bat``.
2008-01-07  RHSK_  Release changelevel was in ``issue.cgi``, now in ``data.py``.
2010-10-06  GDR_   Use the project updater to register new releases.
2012-09-13  RB_    Don’t copy the ``readme.txt`` to the release directory, since it no longer has that dual role; make the ZIP file on a Unix box with the zip utility, since compatibility has improved.
2013-03-08  GDR_   Add testing step.
2012-09-24  RB_    Make sure ZIP files contain files with Windows line endings. Use a fresh Perforce client to avoid any possibility of a clash with working files. Different archive name for custom variants.
2013-03-20  GDR_   Ensure that manual HTML is up to date before making a release.
2014-01-13  GDR_   Make procedure less error-prone by giving exact sequence of commands (where possible) based on experience of release 1.112.0.
2016-01-28  RB_    Git repository renamed from mps-temporary to mps.
2018-07-30  GDR_   Git Fusion moved to perforce.ravenbrook.com.
2020-07-28  PNJ_   Updated licence text.
==========  =====  ==========================================================

.. _RB: mailto:rb@ravenbrook.com
.. _NB: mailto:nb@ravenbrook.com
.. _RHSK: mailto:rhsk@ravenbrook.com
.. _GDR: mailto:gdr@ravenbrook.com
.. _PNJ: mailto:pnj@ravenbrook.com

C. Copyright and License
------------------------

Copyright © 2002–2020 `Ravenbrook Limited <https://www.ravenbrook.com/>`_.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

