# Encrypt/Decrypt Text API with Alogrithm aes-256-cbc

## Set your own port
Set your own configuration file (src/main/resources/application.properties) like this:
```
port=<your-own-port>
```

## To Encrypt:
Make JSON Payload Request like below:
```
{
  "text": "your-own-text",
  "key": "your-own-secret-key"
}
```
After fill the payload, then call endpoint /api/encrypt with POST Method. You will get result of the encryption

## To Decrypt
Make JSON Payload Request like below:
```
{
  "text": "your-encrypted-text",
  "key": "your-own-secret-key"
}
```
After fill the payload, then call endpoint /api/decrypt with POST Method. You will get result of the decryption
