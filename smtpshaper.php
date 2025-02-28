#!/usr/bin/php
<?php

/**
 * smtpshaper : a policy daemon for postfix to limit emails sent by AlternC's accounts.
 * limit an email to 100 different IP per day and 1000 messages per hour & 5000 per day
 * above this limit, the sender will be blocked, unless he/she is in the whitelist
 */

// Set the conf values below to new values in this configuration file:
// (json-encoded)
$conffile="/etc/alternc/smtpshaper.conf";
$whitelistfile="/etc/alternc/smtpshaper.whitelist.conf";

// default values : 
$conf=array(
    // which ip & port shall the policy daemon listen:
	"listen"=> "127.0.0.1",
	"port"=> "10023",
    // limit to 100 different IP per day : 
	"shape_ip"=> array( "86400"=> 100 ),
    // limit to 1000 recipients per hour & 5000 per day : 
	"shape_rcpts"=> array( "3600"=> 1000, "86400"=> 5000 ),
    // The sender will be "mail" by default
    "mail_sender" => "mail",
    // The mail template
    "mail_file" => "/etc/alternc/smtpshaper.fr.txt",
    // you may add emails here, that will also receive the sent mail:
	"mail_bcc"=> array(  ),
    // those are not subject to shaping:
    "whitelist" => array( ),
    // the IP blocs below (IPv6 currently not supported) are considered as 1 single IP address (eg: google for 209.85.128.0/17)
    "singleip" => array( "209.85.128.0/17" ),
);


// conf file overwrite *every* values at once (not only the one stated in the conf file...) 
if (file_exists($conffile)) {
    $testconf=json_decode(file_get_contents($conffile),true);
    if (is_array($testconf)) {
        $conf=array_merge($conf,$testconf);
    } else {
        echo date("Y-m-d H:i:s")." file $conffile has errors, ignored.\n";
    }
}

echo date("Y-m-d H:i:s")." starting smtpshaper daemon\n";
$main_sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);

// we store a local memory of the blocked accounts in here:
$blocklist=array(); // cache for 10 min only => after that SASLAUTHD MUST HAVE reloaded its cache and we are denied anyway
// we also cache which email address has which ID in the DB:
$addrcache=array();
// we only keep those attributes from postfix :
$attrkeep=array(
    "protocol_state", "request", "client_address", "sasl_username",
    "recipient_count", 
);
// auto reload based on filemtime if exists.
$whitelist=array();

socket_set_option($main_sock, SOL_SOCKET, SO_REUSEADDR, 1);
if (!socket_bind($main_sock, $conf["listen"], $conf["port"])) {
    echo date("Y-m-d H:i:s")." can't bind on socket, please check\n";
}
socket_listen($main_sock);

// create a list of all the clients that will be connected to us..
// add the listening socket to this list
$clients = array($main_sock);

/*
 This is the list of key/values pairs received for each connexion.
 when we have an empty line, we push these values to the main function,
 which answers and remove the entry
*/
$attributes=array();

while (true) {
    // create a copy, so $clients doesn't get modified by socket_select()
    $read = $clients;
    $write = null; $except = null;
    // get a list of all the clients that have data to be read from
    // if there are no clients with data, go to next iteration
    if (socket_select($read, $write, $except, 10) < 1)
        continue;

    // check if there is a client trying to connect (sock is inside read
    if (  ($key = array_search($main_sock, $read)) !==  false) {
        // remove the listening socket from the clients-with-data array 
        unset($read[$key]);        
        // accept the client, and add him to the $clients array
        $clients[] = $newsock = socket_accept($main_sock);
        end($clients); // get the latest key in clients
        $clientid=key($clients);
        $attributes[$clientid]=array(); // empty key/value pairs
        
        socket_getpeername($newsock, $ip);
        echo date("Y-m-d H:i:s")." New client $clientid connected: {$ip}\n";
    }

    // loop through all the clients that have data to read from
    foreach ($read as $read_sock) {
        // read a line
        // socket_read show errors when the client is disconnected, silence the error messages
        $data = @socket_read($read_sock, 1024, PHP_NORMAL_READ);

        $clientid = array_search($read_sock, $clients);
        // when the client is disconnected
        if ($data === false) {
            unset($clients[$clientid]);
            unset($attributes[$clientid]);
            echo date("Y-m-d H:i:s")." client $clientid disconnected.\n";
            continue;
        }
        $data = trim($data);
        if (!empty($data)) {
            // add the attribute
            if (preg_match('#^([^=]*)=(.*)$#',$data,$mat)) {
                if (in_array($mat[1],$attrkeep)) 
                    $attributes[$clientid][$mat[1]]=$mat[2]; // we store the attribute key/value
            }
        } else {
            // empty line means end of attributes, launch the main process
            // this function call will reply with a policy server answer
            $action = sasl_stats($attributes[$clientid]);
            socket_write($read_sock,"action=".$action."\n\n");
            // We can empty the attribute store for this client
            $attributes[$clientid]=array();
        }

    } // end of reading foreach socket
} // infinite loop (daemon)


/**
 * check the attributes from postfix ($attrs) and remember how many mails & ip we saw for a customer. 
 * if the customer is above the result, trigger the denial and lock its account (here in the cache for 1H + in AlternC DB)
 * return the action that we should send back to postfix
 */
function sasl_stats($attrs) {
    global $addrcache,$conf,$whitelist;

    // change the client address if it's inside one of the singleip blocs
    $attrs["client_address"]=simplify_ip($attrs["client_address"]);
    
    if ($attrs["request"]!="smtpd_access_policy") {
        return "DUNNO";
    }
    if (!isset($attrs["sasl_username"]) || !$attrs["sasl_username"]) {
        echo date("Y-m-d H:i:s")." email without sasl_username, OK\n";
        return "OK";
    }
    if (!isset($addrcache[$attrs["sasl_username"]])) {
        $addrcache[$attrs["sasl_username"]]=get_address_by_name($attrs["sasl_username"]);
    }
    $addrid = $addrcache[$attrs["sasl_username"]];
    
    // at DATA time, we log :
    if ($attrs["protocol_state"]=="DATA") {
        $rcptcount=intval($attrs["recipient_count"]);
        if ($rcptcount==0) {
            return "OK";
        }
        echo date("Y-m-d H:i:s")." sent an email with $rcptcount recipients from ".$attrs["client_address"]." by ".$attrs["sasl_username"]." (id ".$addrid.")\n";
        mq("INSERT INTO saslstat SET address_id=".$addrid.", rcptcount=".intval($attrs["recipient_count"]).", ip='".addslashes($attrs["client_address"])."';");
    }
    // at RCPT AND DATA time, we block :
    // auto reload whitelist if necessary
    auto_reload_whitelist();
    if (!in_array($attrs["sasl_username"],$whitelist) && is_it_blocked($addrid,$attrs["client_address"])) {
        return "521 Rejected";
    } else {
        return "OK";
    }

    return "OK";
}


/*
 * reload the whitelist file if it has changed
 * since last time
 */
function auto_reload_whitelist() {
    global $whitelist,$whitelistfile;
    static $whitelistts=0;
    clearstatcache();
    if (!file_exists($whitelistfile)) {
        $whitelist=array();
        $whitelistts=0;
        return;
    }
    if (filemtime($whitelistfile)>$whitelistts) {
        $whitelist=array();
        $f=fopen($whitelistfile,"rb");
        if ($f) {
            while($s=fgets($f,1024)) {
                $s=trim($s);
                if (substr($s,0,1)=="#") continue;
                $whitelist[]=$s;
            }
            fclose($f);
        }
        $whitelistts=filemtime($whitelistfile);
        echo date("Y-m-d H:i:s")." reloaded whitelist file $whitelistfile (has now ".count($whitelist)." entries)\n";
        return;
    }
}


/*
 * check, using shape_ip and shape_rcpt
 * if a user has gone above the allowed count.
 * if yes, add it to the blocklist (by id) and lock its account,
 * and send an email
 */
function is_it_blocked($addrid,$ip) {
    global $blocklist,$shape_rcpts,$conf;

    $expire=time()-600;
    foreach($blocklist as $addr=>$time) {
        if ($time<$expire) unset($blocklist[$addr]);
    }
    
    if (isset($blocklist[$addrid])) return true;

    foreach($conf["shape_rcpts"] as $time => $counter)  {
        $compare = mysqli_fetch_array(mq("SELECT SUM(rcptcount) AS counter FROM saslstat WHERE address_id=".intval($addrid)." AND cdate>DATE_SUB(NOW(), INTERVAL $time SECOND);"));
        if ($compare["counter"] >= $counter) {
            block($addrid,"Ce compte a envoyé des mails à ".$compare["counter"]." addresses en ".intval($time/3600)."h.");
            $blocklist[$addrid]=time();
            return true;
        }
    } // for each shaping on RCPTcount

    foreach($conf["shape_ip"] as $time => $counter)  {
        $compare = mysqli_fetch_array(mq("SELECT COUNT(DISTINCT ip) AS counter FROM saslstat WHERE address_id=".intval($addrid)." AND cdate>DATE_SUB(NOW(), INTERVAL $time SECOND);"));
        if ($compare["counter"] >= $counter) {
            block($addrid,"Ce compte a envoyé des mails depuis ".$compare["counter"]." adresses IP différentes en ".intval($time/3600)."h.");
            $blocklist[$addrid]=time();
            return true;
        }
    } // for each shaping on IP
    // not blocked :
    return false;
} // compute_block

/**
 * when we block an account, we do it here : 
 * - disable it in alternc
 * - send an email to the customer
 */
function block($addrid,$msg) {
    global $addrcache,$conf;
    $email = array_search($addrid,$addrcache);
    echo date("Y-m-d H:i:s")." EMAIL $email BLOCKED with msg : $msg\n";
    mq("UPDATE address SET password=concat('*',password) WHERE id=".intval($addrid).";");
    $fields=array(
        "HOSTNAME"=>gethostname(),
        "EMAIL" => $email,
        "MESSAGE" => $msg
    );
    $to = mysqli_fetch_array(mq("SELECT m.mail AS recipient FROM membres m, domaines d, address a WHERE a.id=".intval($addrid)." AND a.domain_id=d.id AND d.compte=m.uid;"));
    mail_tpl($conf["mail_sender"],$to["recipient"],$conf["mail_file"],$fields);
    foreach($conf["mail_bcc"] as $to) {
        mail_tpl($conf["mail_sender"],$to,$conf["mail_file"],$fields);
    }
}


function get_address_by_name($email) {
    list($mail,$dom)=explode("@",$email);
    $s=mysqli_fetch_array(mq("SELECT id FROM domaines WHERE domaine='".addslashes($dom)."';"));
    if (!$s) { echo date("Y-m-d H:i:s")." Mail not found for domain $dom\n"; return 0; }
    $id=mysqli_fetch_array(mq("SELECT id FROM address WHERE domain_id=".$s["id"]." AND address='".addslashes($mail)."';"));
    if (!$id) { echo date("Y-m-d H:i:s")." email $email not found\n"; return 0; }
    return $id["id"];
}


function mq($query) {
    global $db;
    if (!$db) mq_connect();
    if (!$db) return false;
    try {
        $res = mysqli_query($db,$query);
    } catch (Exception $e) {
        // no need to manage it here: on some servers it's not throwing an exception anyway :/ 
    }
    // in case of "mysql server has gone away", try to reconnect (once)
    if (mysqli_errno($db)==2006) {
        // reconnect once 
        mq_connect();
        if (!$db) return false;
        $res = mysqli_query($db,$query);
    }
    if (mysqli_errno($db)) {
        echo date("Y-m-d H:i:s")." can't reconnect to mysql server\n";
        return false;
    }
    return $res;
}

/**
 * connect to a mysql server using AlternC's parameters
 * return true if it worked
 */
function mq_connect() {
    global $db;
    // use AlternC's configuration:
    $config_file = fopen('/etc/alternc/my.cnf', 'r');
    while (false!== ($line = fgets($config_file))) {
        if (preg_match('/^([A-Za-z0-9_]*) *= *"?(.*?)"?$/', trim($line), $regs)) {
            switch ($regs[1]) {
            case "user":
                $L_MYSQL_LOGIN = $regs[2];
                break;
            case "password":
                $L_MYSQL_PWD = $regs[2];
                break;
            case "host":
                $L_MYSQL_HOST = $regs[2];
                break;
            case "database":
                $L_MYSQL_DATABASE = $regs[2];
                break;
            }
        }
    }
    
    fclose($config_file);
    $db = mysqli_connect($L_MYSQL_HOST, $L_MYSQL_LOGIN, $L_MYSQL_PWD);
    if (!$db) return false;
    return mysqli_select_db($db,$L_MYSQL_DATABASE);
}

/**
 * send from $from to $to the content of the $mailfile file
 * by doing a substitution of %%KEY%% to VALUES in the $fields hash
 */
function mail_tpl($from, $to, $mailfile, $fields) {
    $f=fopen($mailfile,"rb");
    $subject=trim(fgets($f,1024));
    $text="";
    while($s=fgets($f,1024)) $text.=$s;
    reset($fields);
    while (list($k,$v)=each($fields)) {
        $subject=str_replace("%%".$k."%%",$v,$subject);
        $text=str_replace("%%".$k."%%",$v,$text);
    }
    return mail($to,$subject,$text,"Content-Type: text/plain; charset=\"utf-8\"\nFrom: $from\nReply-to: $from\nReturn-Path: $from\n");
}

function simplify_ip($ip) {
    global $conf;
    if (!filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)) return $ip; // no change for non-ipv4 IP addresses
    $ip=ip2long($ip);
    foreach($conf["singleip"] as $bloc) {
        // if this is a proper ip/prefix bloc, we compute its start and end IP address as a long : 
        if (preg_match('#^([0-9\.]+)/([0-9]+)$#',$bloc,$mat)) {
            $start=ip2long($mat[1]);
            $end=ip2long($mat[1])+(1<<(32-$mat[2]))-1;
        } else {
            continue;
        }
        if ($ip<=$end && $ip>=$start) $ip=$start;
    }
    return long2ip($ip);
}
