cord-robot
----------

This contains both python libraries and resource (Keyword) files for the CORD
project.

The resource files are imported using:
https://github.com/rasjani/robotframework-importresource .

To use, import the library and resource files with:

.. code:: robotframework

    Library   CORDRobot
    Library   ImportResource  resources=CORDRobot

Development notes
-----------------

Add python libraries to ``src/CORDRobot``,  and include them in the
``__init__.py``.

Add resource files to the ``src/CORDRobot/rf-resources`` with the extension
``.resource``

Run ``tox`` to test - see list of test commands run in ``tox.ini``.
