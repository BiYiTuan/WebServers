# HttpWebSocketServers
A collection of http and websocket servers built to demo **Java SE** NIO.2, `AIO` libraries.

All examples contain the basic structure required for performing a large number of requests and responses without crashing or running slowly.

(Optional) Configure your keystore:
  1. If you have a proper certificate then follow these [steps](https://docs.oracle.com/cd/E19509-01/820-3503/ggfen/index.html) to create a keystore using your certificate otherwise proceed to step 2.
  2. `keytool -genkey -keyalg RSA -alias selfsigned -keystore keystore.jks -storepass password -validity 360 -keysize 2048`
  3. Place the keystore in /FastHttpsServer
  4. Visit server URL in browser
  5. Trust and Add certificate exception
