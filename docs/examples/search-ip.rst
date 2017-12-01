Search Information on an IP
---------------------------

.. code-block:: python

    #!/usr/bin/env python
    # onyphe_ip.py
    #
    # Author: Sebastien Larinier

    import onyphe

    API_KEY = "YOUR_API_KEY"
    ip = sys.argv['1']
    #Input validation
    if len(sys.argv) == 1:
        print('Usage: %s ' % sys.argv[0])
        sys.exit(1)
    try:
        # Setup the ap
        api = onyphe.Onyphe(API_KEY)
        # Perform the search
        result = api.ip(ip)
        print(json.dumps(result))
    except Exception as e:
        print('Error: %s' % e)
        sys.exit(1)


