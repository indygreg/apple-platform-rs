.. _apple_codesign_rcodesign_notarizing:

==========================================
Notarizing and Stapling with ``rcodesign``
==========================================

Submit Notarizations with ``notary-submit``
===========================================

You can notarize a signed asset via ``rcodesign notary-submit``.

Notarization requires an App Store Connect API Key. See
:ref:`apple_codesign_app_store_connect_api_key` for instructions on how
to obtain one.

Assuming you used ``rcodesign encode-app-store-connect-api-key`` to produce
a JSON file with all the API Key information, simply specify ``--api-key-file``
to define the path to this JSON file.

To notarize an already signed asset::

    rcodesign notary-submit \
      --api-key-file ~/.appstoreconnect/key.json \
      path/to/file/to/notarize

By default ``notarize-submit`` just uploads the asset to Apple. To wait
on its notarization result, add ``--wait``::

    rcodesign notary-submit \
      --api-key-file ~/.appstoreconnect/key.json \
      --wait \
      path/to/file/to/notarize

Or to wait and automatically staple the file if notarization was successful::

    rcodesign notary-submit \
      --api-key-file ~/.appstoreconnect/key.json \
      --staple \
      path/to/file/to/notarize

Stapling With ``staple``
========================

If an asset was already notarized, you can attempt to *staple* (read: attach)
the *notarization ticket* to that entity via the ``staple`` command::

    rcodesign staple path/to/file/to/staple

.. tip::

   It is possible to staple any asset, not just those notarized by you.

Checking on Submitted Notarizations
===================================

Notarization is an asynchronous process: you first submit an asset to Apple then
you wait for an indefinite amount of time (often a few dozen seconds) for
Apple's servers to scan the asset and issue a notarization ticket.

If a notarization operation is interrupted or if you want to check on its
status, there are a few support commands to query Apple's servers.

``notary-wait`` can be used to wait on a previously submitted notarization
request to finish::

   rcodesign notary-wait
     --api-key-file ~/.appstoreconnect/key.json \
     <submission ID>

Here, ``<submission ID>`` is an identifier issued by Apple and printed when
running ``rcodesign notary-submit``.

``notary-log`` can be used to retrieve the notarization log for a submission
identifier::

   rcodesign notary-log
     --api-key-file ~/.appstoreconnect/key.json \
     <submission ID>
