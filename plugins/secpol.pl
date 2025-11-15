#-----------------------------------------------------------
# secpol.pl
# Parse Security Policy data from SECURITY hive
# Extracts privileges, system access rights, and security descriptors
# for accounts in Policy\Accounts
#
# Change history:
#   2024-11-15 - created
#
# References:
#   https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
#
# Category: Security
#-----------------------------------------------------------
package secpol;
use strict;

my %config = (hive          => "Security",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              MITRE         => "",
              version       => 20241115);

sub getConfig{return %config}
sub getShortDescr {
	return "Parse Security Policy accounts and privileges";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

# Privilege LUID to name mapping
my %privileges = (
    2  => "SeCreateTokenPrivilege",
    3  => "SeAssignPrimaryTokenPrivilege",
    4  => "SeLockMemoryPrivilege",
    5  => "SeIncreaseQuotaPrivilege",
    6  => "SeMachineAccountPrivilege",
    7  => "SeTcbPrivilege",
    8  => "SeSecurityPrivilege",
    9  => "SeTakeOwnershipPrivilege",
    10 => "SeLoadDriverPrivilege",
    11 => "SeSystemProfilePrivilege",
    12 => "SeSystemtimePrivilege",
    13 => "SeProfileSingleProcessPrivilege",
    14 => "SeIncreaseBasePriorityPrivilege",
    15 => "SeCreatePagefilePrivilege",
    16 => "SeCreatePermanentPrivilege",
    17 => "SeBackupPrivilege",
    18 => "SeRestorePrivilege",
    19 => "SeShutdownPrivilege",
    20 => "SeDebugPrivilege",
    21 => "SeAuditPrivilege",
    22 => "SeSystemEnvironmentPrivilege",
    23 => "SeChangeNotifyPrivilege",
    24 => "SeRemoteShutdownPrivilege",
    25 => "SeUndockPrivilege",
    26 => "SeSyncAgentPrivilege",
    27 => "SeEnableDelegationPrivilege",
    28 => "SeManageVolumePrivilege",
    29 => "SeImpersonatePrivilege",
    30 => "SeCreateGlobalPrivilege",
    31 => "SeTrustedCredManAccessPrivilege",
    32 => "SeRelabelPrivilege",
    33 => "SeIncreaseWorkingSetPrivilege",
    34 => "SeTimeZonePrivilege",
    35 => "SeCreateSymbolicLinkPrivilege",
);

# System Access flags
my %sysaccess = (
    0x00000001 => "INTERACTIVE_LOGON",
    0x00000002 => "NETWORK_LOGON",
    0x00000004 => "BATCH_LOGON",
    0x00000008 => "SERVICE_LOGON",
    0x00000010 => "PROXY_LOGON",
    0x00000020 => "DENY_INTERACTIVE_LOGON",
    0x00000040 => "DENY_NETWORK_LOGON",
    0x00000080 => "DENY_BATCH_LOGON",
    0x00000100 => "DENY_SERVICE_LOGON",
    0x00000200 => "REMOTE_INTERACTIVE_LOGON",
    0x00000400 => "DENY_REMOTE_INTERACTIVE_LOGON",
);

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	::logMsg("Launching secpol v.".$VERSION);
	::rptMsg("secpol v.".$VERSION);
	::rptMsg("(".$config{hive}.") ".getShortDescr()."\n");
	
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;

	my $key_path = "Policy\\Accounts";
	my $key;
	
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg($key_path);
		::rptMsg("LastWrite Time: ".::format8601Date($key->get_timestamp())."Z");
		::rptMsg("");
		
		my @subkeys = $key->get_list_of_subkeys();
		
		if (scalar(@subkeys) > 0) {
			foreach my $s (@subkeys) {
				my $sid = $s->get_name();
				::rptMsg("="x70);
				::rptMsg("SID: ".$sid);
				::rptMsg("LastWrite: ".::format8601Date($s->get_timestamp())."Z");
				::rptMsg("-"x70);
				
				# Parse ActSysAc (Active System Access)
				eval {
					my $actsysac = $s->get_subkey("ActSysAc");
					my @values = $actsysac->get_list_of_values();
					if (scalar(@values) > 0) {
						my $data = $values[0]->get_data();
						parseSystemAccess($data);
					}
				};
				
				# Parse Privilgs (Privileges)
				eval {
					my $privilgs = $s->get_subkey("Privilgs");
					my @values = $privilgs->get_list_of_values();
					if (scalar(@values) > 0) {
						my $data = $values[0]->get_data();
						parsePrivileges($data);
					}
				};
				
				# Parse SecDesc (Security Descriptor)
				eval {
					my $secdesc = $s->get_subkey("SecDesc");
					my @values = $secdesc->get_list_of_values();
					if (scalar(@values) > 0) {
						my $data = $values[0]->get_data();
						parseSecurityDescriptor($data);
					}
				};
				
				# Parse Sid
				eval {
					my $sidkey = $s->get_subkey("Sid");
					my @values = $sidkey->get_list_of_values();
					if (scalar(@values) > 0) {
						my $data = $values[0]->get_data();
						my $parsed_sid = parseSID($data);
						::rptMsg("");
						::rptMsg("[Sid Binary Value]");
						::rptMsg("  Parsed SID: ".$parsed_sid);
						if ($parsed_sid ne $sid) {
							::rptMsg("  WARNING: SID mismatch with key name!");
						}
					}
				};
				
				::rptMsg("");
			}
		}
		else {
			::rptMsg($key_path." has no subkeys.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}
}

sub parseSystemAccess {
	my $data = shift;
	return if (length($data) < 4);
	
	my $flags = unpack("V", $data);
	
	::rptMsg("");
	::rptMsg("[ActSysAc - System Access Rights]");
	::rptMsg("  Flags: 0x".sprintf("%08X", $flags)." (".$flags.")");
	
	my @active;
	foreach my $flag (sort {$a <=> $b} keys %sysaccess) {
		if ($flags & $flag) {
			push @active, $sysaccess{$flag};
		}
	}
	
	if (@active) {
		::rptMsg("  Active permissions:");
		foreach my $perm (@active) {
			::rptMsg("    - ".$perm);
		}
	}
	else {
		::rptMsg("  No standard flags set");
	}
}

sub parsePrivileges {
	my $data = shift;
	return if (length($data) < 8);
	
	my ($priv_count, $control) = unpack("VV", substr($data, 0, 8));
	
	::rptMsg("");
	::rptMsg("[Privilgs - Privilege Set]");
	::rptMsg("  Privilege Count: ".$priv_count);
	::rptMsg("  Control: 0x".sprintf("%08X", $control));
	
	if ($priv_count == 0) {
		::rptMsg("  No privileges assigned");
		return;
	}
	
	my $offset = 8;
	for (my $i = 0; $i < $priv_count; $i++) {
		last if ($offset + 12 > length($data));
		
		my ($luid_low, $luid_high, $attributes) = unpack("VVV", substr($data, $offset, 12));
		my $priv_name = $privileges{$luid_low} || "Unknown (LUID $luid_low)";
		
		::rptMsg("  Privilege ".($i+1).":");
		::rptMsg("    LUID: 0x".sprintf("%08X", $luid_low)." (decimal: ".$luid_low.")");
		::rptMsg("    Name: ".$priv_name);
		::rptMsg("    Attributes: 0x".sprintf("%08X", $attributes));
		
		$offset += 12;
	}
}

sub parseSecurityDescriptor {
	my $data = shift;
	return if (length($data) < 20);
	
	my ($revision, $sbz1, $control) = unpack("CCv", substr($data, 0, 4));
	my ($owner_offset, $group_offset, $sacl_offset, $dacl_offset) = 
		unpack("VVVV", substr($data, 4, 16));
	
	::rptMsg("");
	::rptMsg("[SecDesc - Security Descriptor]");
	::rptMsg("  Revision: ".$revision);
	::rptMsg("  Control: 0x".sprintf("%04X", $control));
	
	# Parse control flags
	my @flags;
	push @flags, "SE_OWNER_DEFAULTED" if ($control & 0x0001);
	push @flags, "SE_GROUP_DEFAULTED" if ($control & 0x0002);
	push @flags, "SE_DACL_PRESENT" if ($control & 0x0004);
	push @flags, "SE_DACL_DEFAULTED" if ($control & 0x0008);
	push @flags, "SE_SACL_PRESENT" if ($control & 0x0010);
	push @flags, "SE_SACL_DEFAULTED" if ($control & 0x0020);
	push @flags, "SE_SELF_RELATIVE" if ($control & 0x8000);
	
	::rptMsg("  Flags: ".join(", ", @flags)) if (@flags);
	
	# Parse DACL
	if ($dacl_offset > 0 && $dacl_offset < length($data)) {
		parseACL($data, $dacl_offset, "DACL");
	}
	
	# Parse Owner SID
	if ($owner_offset > 0 && $owner_offset < length($data)) {
		my $owner_sid = parseSID(substr($data, $owner_offset));
		::rptMsg("  Owner SID: ".$owner_sid);
	}
	
	# Parse Group SID
	if ($group_offset > 0 && $group_offset < length($data)) {
		my $group_sid = parseSID(substr($data, $group_offset));
		::rptMsg("  Group SID: ".$group_sid);
	}
}

sub parseACL {
	my ($data, $offset, $acl_type) = @_;
	return if ($offset + 8 > length($data));
	
	my ($acl_revision, $sbz1, $acl_size, $ace_count) = 
		unpack("CCvv", substr($data, $offset, 8));
	
	::rptMsg("  ".$acl_type.":");
	::rptMsg("    ACL Size: ".$acl_size." bytes");
	::rptMsg("    ACE Count: ".$ace_count);
	
	my $ace_offset = $offset + 8;
	for (my $i = 0; $i < $ace_count; $i++) {
		last if ($ace_offset + 8 > length($data));
		
		my ($ace_type, $ace_flags, $ace_size, $access_mask) = 
			unpack("CCvV", substr($data, $ace_offset, 8));
		
		my %ace_types = (
			0x00 => "ACCESS_ALLOWED_ACE",
			0x01 => "ACCESS_DENIED_ACE",
			0x02 => "SYSTEM_AUDIT_ACE",
			0x03 => "SYSTEM_ALARM_ACE",
		);
		
		my $ace_type_name = $ace_types{$ace_type} || sprintf("Unknown (0x%02X)", $ace_type);
		
		::rptMsg("    ACE ".($i+1).":");
		::rptMsg("      Type: ".$ace_type_name);
		::rptMsg("      Flags: 0x".sprintf("%02X", $ace_flags));
		::rptMsg("      Access Mask: 0x".sprintf("%08X", $access_mask));
		
		# Parse SID in ACE
		my $sid_offset = $ace_offset + 8;
		if ($sid_offset < length($data)) {
			my $sid_string = parseSID(substr($data, $sid_offset));
			::rptMsg("      SID: ".$sid_string);
		}
		
		$ace_offset += $ace_size;
	}
}

sub parseSID {
	my $data = shift;
	return "Invalid SID" if (length($data) < 8);
	
	my ($revision, $sub_auth_count) = unpack("CC", substr($data, 0, 2));
	my $authority = unpack("N", substr($data, 4, 4));  # Big-endian
	
	return "Invalid SID (truncated)" if (length($data) < 8 + ($sub_auth_count * 4));
	
	my $sid_string = "S-".$revision."-".$authority;
	
	for (my $i = 0; $i < $sub_auth_count; $i++) {
		my $offset = 8 + ($i * 4);
		my $sub_auth = unpack("V", substr($data, $offset, 4));  # Little-endian
		$sid_string .= "-".$sub_auth;
	}
	
	return $sid_string;
}

1;