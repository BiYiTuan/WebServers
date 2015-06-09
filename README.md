# WebServers
Simple, single class http, https, websocket and websocket secure servers built to demo **Java SE** NIO.2, `AIO` libraries. Examples contain the minimum amount of code required to perform a call without getting any errors.

(Optional) Configure your keystore:
  1. If you have a proper certificate then follow these [steps](https://docs.oracle.com/cd/E19509-01/820-3503/ggfen/index.html) to create a keystore using your certificate otherwise proceed to step 2.
  2. `keytool -genkey -keyalg RSA -alias selfsigned -keystore keystore.jks -storepass password -validity 360 -keysize 2048`
  3. Place the keystore in /WebServers
  4. Visit server URL in browser
  5. Trust and Add certificate exception
