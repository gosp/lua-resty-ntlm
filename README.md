# Intro

`Windows authentication` is always used inside company. `IIS` can enable `Windows authentication` easily. For Nginx users, some solutions aren't friendly: `Nginx Pro` provides ntlm module but it isn't free; [`reverse proxy`](https://stackoverflow.com/questions/21284935/nginx-reverse-proxy-with-windows-authentication-that-uses-ntlm) must setup other server firstly.

The project is inspired by [express-ntlm](https://github.com/einfallstoll/express-ntlm) and [PyAuthenNTLM2](https://github.com/Legrandin/PyAuthenNTLM2/). IIS will trigger windows authentication scenario for each connection. Unlike IIS, the project only trigger ntlm for first requestion. After authentication pass, a cookie will be created.

# Usage
+ install [OpenResty](http://openresty.org/en/linux-packages.html) which integrates Nginx and LuaJIT
+ intall [LuaRocks](https://openresty.org/en/using-luarocks.html) because `ntlm.lua` depends on `struct` module
+ install `struct` module: `sudo /usr/local/openresty/luajit/bin/luarocks install struct`
+ install `iconv` module: `sudo /usr/local/openresty/luajit/bin/luarocks install lua-iconv`
+ save `ntlm.lua` into `/usr/local/openresty/site/lualib`
+ add the following code to `/usr/local/openresty/nginx/conf/nginx.conf`: 
    ```
        access_by_lua_block {
            local ntlm = require('ntlm')
            ntlm.negotiate("ldap://domain.net:389")
        }
    ```
+ restart nginx service: `sudo service openresty restart`