#!/usr/local/bin/tclsh

# cliscript.tcl - Based on "quickscript.tcl"
# Portions Copyright (C) 2012 Paul Halliday <paul.halliday@gmail.com>

# Copyright (C) 2002-2006 Robert (Bamm) Visscher <bamm@sguil.net>
#
# This program is distributed under the terms of version 1.0 of the
# Q Public License.  See LICENSE.QPL for further details.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

########################## GLOBALS ##################################

### Load extended tcl
if [catch {package require Tclx} tclxVersion] {
    puts "Error: Package TclX not found"
    exit
}

set CONFIG "../.inc/config.php"
if {[file exists $CONFIG]} {
    for_file line $CONFIG {
        if { [regexp {^\$([^\s]+)\s+=\s+['"]([^'"]+)['"]} $line match theVar theVal] } {
            set configArray($theVar) $theVal
        }
    }
    set VERSION  $configArray(sgVer)
    set SERVER   $configArray(sgHost)
    set PORT     $configArray(sgPort)
    set PCAP_DIR $configArray(pcapDirectory)
} else {
    puts "I could not find a confguration file"
    exit 1
}

set TYPE [lindex $argv 0]
if { $TYPE == "transcript" } {
    if { $argc == 9 } {
        set USR [lindex $argv 1]
        set SEN [lindex $argv 2]
        set TS  [lindex $argv 3]
        set SID [lindex $argv 4]
        set SIP [lindex $argv 5]
        set DIP [lindex $argv 6]
        set SPT [lindex $argv 7]
        set DPT [lindex $argv 8]
    } else {
        puts "ERROR: Not enough arguments for transcript request"
        exit 1
    }
} elseif { $TYPE == "pcap" } {
    if { $argc == 10 } {
        set USR [lindex $argv 1]
        set SEN [lindex $argv 2]
        set TS  [lindex $argv 3]
        set SID [lindex $argv 4]
        set SIP [lindex $argv 5]
        set DIP [lindex $argv 6]
        set SPT [lindex $argv 7]
        set DPT [lindex $argv 8]
        set PRT [lindex $argv 9]
    } else {
        puts "ERROR: Not enough arguments for pcap request"
        exit 1
    }
} else {
    puts "ERROR: Not enough arguments"
    exit 1
}


#########################################################################
# Package/Extension Requirements
#########################################################################

# Check to see if a path to the tls libs was provided
if { [info exists TLS_PATH] } {

    if [catch {load $TLS_PATH} tlsError] {

        puts "ERROR: Unable to load tls libs ($TLS_PATH): $tlsError"
        DisplayUsage $argv0

    }

}

if { [catch {package require tls} tlsError] } {

    puts "ERROR: The tcl tls package does NOT appear to be installed on this sysem."
    puts "Please see http://tls.sourceforge.net/ for more info."
    exit 1

}


#########################################################################
# Procs 
#########################################################################

# A simple proc to send commands to sguild and catch errors
proc SendToSguild { socketID message } {

    if { [catch {puts $socketID $message} sendError] } {

        # Send failed. Close the socket and exit.
        catch {close $socketID} closeError

        if { [info exists sendError] } { 

            puts "ERROR: Caught exception while sending data: $sendError"

        } else {

            puts "ERROR: Caught unknown exception"

        }

        exit 1

    }

}

# Connect to Sguild
proc ConnectToSguild { } {
    global SERVER PORT USR PWD VERSION

    # Try to connect to sguild
    if [catch {socket $SERVER $PORT} socketID ] {

        # Exit on fail.
        return -code error "ERROR: Connection failed"
    }

    # Successfully connected
    fconfigure $socketID -buffering line

    # Check version compatibality
    if [catch {gets $socketID} serverVersion] {

        # Caught an unknown error
        catch {close $socketID}
        return -code error "ERROR: $serverVersion"
    }

    if { $serverVersion == "Connection Refused." } {

        # Connection refused error
        catch {close $socketID}
        return -code error "ERROR: $serverVersion"
    } 

    if { $serverVersion != $VERSION } {

        # Mismatched versions
        catch {close $socketID}
        return -code error "ERROR: Mismatched versions.\nSERVER= ($serverVersion)\nCLIENT= ($VERSION)"
    }

    # Send the server our version info
    SendToSguild $socketID [list VersionInfo $VERSION]

    # SSL-ify the socket
    if { [catch {tls::import $socketID -ssl2 false -ssl3 false -tls1 true } tlsError] } { 

        catch {close $socketID}
        return -code error "ERROR: $tlsError"
    }

    # Give SSL a sec
    after 1000

    # Send sguild a ping to confirm comms
    SendToSguild $socketID "PING"
    # Get the PONG
    set INIT [gets $socketID]

    #
    # Auth starts here
    #

    # Authenticate with sguild
    SendToSguild $socketID [list ValidateUser $USR $PWD]

    # Get the response. Success will return the users ID and failure will send INVALID.
    if { [catch {gets $socketID} authMsg] } { 

        catch {close $socketID}
        return -code error "ERROR: $authMsg"

    }

    set authResults [lindex $authMsg 1]
    if { $authResults == "INVALID" } { 

        catch {close $socketID}
        return -code error "ERROR: Authentication failed."

    }

    return $socketID

}




#########################################################################
# Main
#########################################################################

# Get users password
set PWD [gets stdin]

flush stdout

if { [catch {ConnectToSguild} socketID] } {
    puts "Could not connect to Sguild: $socketID"
    exit 1
}

# Send info to Sguild
if { $TYPE == "transcript" } {
    set eventInfo "\"$SEN\" \"$TS\" $SID $SIP $DIP $SPT $DPT"

    # Now verify
    if { ![regexp -expanded { ^\".+\"\s\"\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}\:\d{2}\"\s\d+\s\d+\.\d+\.\d+\.\d+\s\d+\.\d+\.\d+\.\d+\s\d+\s\d+$ } $eventInfo match] } {
    
        puts "ERROR: Arguments failed logic tests"
        exit 1
    
    }

    set SESSION_STATE DEBUG
    SendToSguild $socketID [list CliScript $eventInfo]

} elseif { $TYPE == "pcap" } {
    SendToSguild $socketID [list WiresharkRequest $SEN $SID "$TS" $SIP $SPT $DIP $DPT $PRT 0]
}

# Xscript data comes in the format XscriptMainMsg window message
# Tags are HDR, SRC, and DST. They are sent when state changes.

while { 1 } {

    if { [eof $socketID] } { puts "ERROR: Lost connection to server."; exit 1; }

    if { [catch {gets $socketID} msg] } {

        puts "ERROR: $msg"
        exit 1

    }

    if { $TYPE == "pcap" } {
        set cmd [lindex $msg 0]
        if { $cmd == "PcapAvailable" } { 
            set key [lindex $msg 1 ]
            set filename [file tail [lindex $msg 2 ] ]
            puts "filename: $PCAP_DIR/$filename"
            set outFileID [open "$PCAP_DIR/$filename" w]
            if { [catch {ConnectToSguild} dataSocketID] } {
                puts "Could not connect to Sguild: $dataSocketID"
                exit 1
            }
            SendToSguild $dataSocketID [list SendPcap $key]
            fconfigure $dataSocketID -translation binary
            fconfigure $outFileID -translation binary
            if { [catch {fcopy $dataSocketID $outFileID} tmpError] } {
                puts $tmpError
                exit 1
            }
            catch {close $dataSocketID}
            break
        } 
    } elseif { $TYPE == "transcript" } {
        # Strip the command and faux winname from the msg
        set data [lindex $msg 2]

        switch -exact -- $data {

            HDR     { set SESSION_STATE HDR }
            SRC     { set SESSION_STATE SRC }
            DST     { set SESSION_STATE DST }
            DEBUG   { set SESSION_STATE DEBUG }
            DONE    { break }
            ERROR   { set SESSION_STATE ERROR }
            default { puts "${SESSION_STATE}: [lindex $msg 2]" }

        }

        # Exit if agent returns no data after debug
        if { $SESSION_STATE == "DEBUG" && $data == "" } {
            break
        }
    }

}

catch {close $socketID} 
