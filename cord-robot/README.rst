cord-robot
----------

This contains both python libraries and resource files for the CORD project.

The resource files are imported using: https://github.com/rasjani/robotframework-importresource .

To use, import the library and resource files with:

.. code:: robotframework

    Library   CORDRobot
    Library   ImportResource  resources=cord-robot


Development notes
-----------------

Add python libraries to ``src/CORDRobot``.

Add resource files to the ``src/CORDRobot/rf-resources`` with the extension
``.resource``


