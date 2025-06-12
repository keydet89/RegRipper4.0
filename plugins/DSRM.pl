#-----------------------------------------------------------
# DSRMlogonBehavior
# Directory Services Restore Mode (DSRM) is a safe boot mode for Domain controllers
# It has a DSRM admin account that is used for those functions, meaning it does not have logon behaior
# This leads to threat actors with sufficient privlidges being able to modify HKLM\System\CurrentControlSet\Control\Lsa
# and allow DsrmAdminLogonBehaviour to be set to either 1(meaning it can locally logon) or 2(network logon included)
# 

#  Most of this code was copied from the regripper plugins and then i simplied modified it to look for our target values. I take like 5% credit for this :3
# Author: Abdul Mhanni 
# History:
#   20250612 - created
#
# References:
#   https://adsecurity.org/?p=1785
#   https://attack.mitre.org/techniques/T1556/001/
#
#-----------------------------------------------------------
package DSRM;
use strict;

my %config = (hive          => "system",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              category      => "persistence",
              MITRE         => "T1556\.001",
              output        => "report",
              version       => 20250612);

sub getConfig{return %config}
sub getShortDescr {
    return "Checks DsrmAdminLogonBehaviour value for persistence";
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

my %dsrm_settings = (0 => "Default - DSRM account follows deny network logon setting",
                     1 => "ENABLED local logon - Allows local console logons by DSRM account",
                     2 => "ENABLED network logon - Allows network logons by DSRM account");

sub pluginmain {
    my $class = shift;
    my $hive = shift;
    ::logMsg("Launching DSRM v.".$VERSION);
    ::rptMsg("DSRM v.".$VERSION);
    ::rptMsg("(".getHive().") ".getShortDescr());
    ::rptMsg("MITRE: ".$config{MITRE}." (".$config{category}.")");
    ::rptMsg("");
    
    my $reg = Parse::Win32Registry->new($hive);
    my $root_key = $reg->get_root_key;
    
    # First thing to do is get the ControlSet00x marked current
    my $current;
    my $key_path = 'Select';
    my $key;
    if ($key = $root_key->get_subkey($key_path)) {
        $current = $key->get_value("Current")->get_data();
        my $ccs = "ControlSet00".$current;
        $key_path = $ccs.'\\Control\\LSA';
        if ($key = $root_key->get_subkey($key_path)) {
            ::rptMsg($key_path);
            ::rptMsg("LastWrite: ".::format8601Date($key->get_timestamp())."Z");
            ::rptMsg("");
            
            eval {
                my $dsrm = $key->get_value("DsrmAdminLogonBehaviour")->get_data();
                ::rptMsg("DsrmAdminLogonBehaviour value = ".$dsrm." [".$dsrm_settings{$dsrm}."]");
                
                if ($dsrm == 1 || $dsrm == 2) {
                    ::rptMsg("");
                    ::rptMsg("ALERT! High likelihood of persistence detected. DSRM admin account should not");
                    ::rptMsg("be able to have local/network logons in normal configurations.");
                    ::rptMsg("");
                    ::rptMsg("This setting allows the built-in Directory Services Restore Mode (DSRM) administrator account");
                    ::rptMsg("to log on to a domain controller, potentially enabling persistence mechanisms.");
                }
            };
            
            if ($@) {
                ::rptMsg("DsrmAdminLogonBehaviour value not found.");
                ::rptMsg("Default behavior (value 0) is implied - DSRM account cannot log on normally.");
            }
        }
        else {
            ::rptMsg($key_path." not found.");
        }
    }
    else {
        ::rptMsg($key_path." not found.");
    }
    
    ::rptMsg("");
    ::rptMsg("Analysis Tip: The DsrmAdminLogonBehaviour registry value when set to 1 or 2 allows the DSRM");
    ::rptMsg("administrator account to log on to a domain controller as any other account would");
    ::rptMsg("Thisalmost always indicate an attacker has established persistence as its a break glass account that most admins dont even know about. Good luck! ");
    ::rptMsg("");
    ::rptMsg("Ref: https://adsecurity.org/?p=1785");
}
1;
