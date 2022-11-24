This set of scripts allows to download, parse and aggregate BGP announcement dumps from open repositories to be used in asmap construction.

### Pre-reqs

``./setup.sh``

### Use

0. ``./prepare.sh`` deletes old data.
1. ``./download_dumps.py`` downloads RIPE dumps for a selected date (configured in the file) to the `dumps` folder.
2. ``./quagga_parse.py`` reads dumps from the `dumps` folder and
writes the human readable interpretation to the `paths` folder.
3. ``./quagga_aggregate.py`` goes through the interpreted dumps in ``paths`` folder, aggregates paths and assigns every IP prefix to the first element of the common suffix of the asn path.

Resulting ``prefix_asns.out`` can be fed to ``../buildmap.py``.

### Rationale

Consider the following scenario:
1.2.3.4: A -> B -> C -> X
1.2.3.4: A -> F -> C -> X

In this case, {C, X} is the common suffix, and we will map 1.2.3.4 to C, because C represents the single infrastructure required to reach that IP address.

Note that diversifying by C would implicitly diversify by X too.
