#ElytronAuthCustomRelam


 Wildfly Elytron secutiry system custom auth realm demo 
 
 ## To build
 
 mvn clean package
 
 
 ## To deploy to server



Now build CustomUndertowFilter and run the cli file to create the WildFly module
<WILDFLY_HOME>/bin/jboss-cli.sh --connect --file=add-custom-module.cli

To add the custom realm to server, add the following configuration in the elytron subsystem.
 
 
- Under security-realms 
 
 ```
<security-realms>

	<custom-realm name="MyRealm" module="lk.kana.elytron.custom-relam" class-name="lk.kana.elytron.custom_relam.MyRealm"/>
	
...

</security-realms>
```

- Add it to security domain

```
<security-domain ...>

	 <realm name="MyRealm" .../>

</security-domain>

```  

