# PHP-Scanner

PHP-Scanner is a tool for finding PHP malware, it is written in Rust.

It is licensed under the BSD license.

## Usage

php-scanner [OPTIONS] \<directory\>

```
OPTIONS:
    -c <threads>        Set the maximum number of threads to use
    -t <timeout>        Set the timeout on scanning each file

ARGS:
    <directory>    Sets the directory to scan (it will also scan all directories inside)
```

Matches are saved to scan.log