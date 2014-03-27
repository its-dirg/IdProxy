Run server
==========

To start the IdProxy server use this command: ::

    python idproxy_server.py op_conf idp_conf sp_conf

| You may call your configuration files whatever you want, this is just an example.
* op_conf
    Represents the file op_conf.py and you can find an example of the configuration file in op_conf.example.
* idp_conf
    Represents the file idp_conf.py and you can find an example of the configuration file in idp_conf.example.
* sp_conf
    Represents the file sp_conf.py and you can find an example of the configuration file in sp_conf.example.
|
The program always takes these three arguments, even though you are not using OP and/or IdP configurations.
The server configuration must alway be in the file server_conf.py and you will find an example in the file server_conf.example.