#-----------------------------------------------------------
# edid_tln.pl
# Gets Properties time stamps for monitors beneath the Enum\DISPLAY
# key, and names each monitor using its EDID data
#
# History
#   20261017 - created, copied from edid.pl
#
# References:
#   VESA Enhanced EDID (E-EDID) Standard, Release A, Rev. 2 (EDID 1.4)
#   https://learn.microsoft.com/en-us/windows-hardware/drivers/install/devpkey-device-installdate
#
# copyright 2026 Sujay Adkesar
# author: Sujay Adkesar, sujayadkesar2002@gmail.com
#-----------------------------------------------------------
package edid_tln;
use strict;

my %config = (hive          => "System",
              MITRE         => "",
              category      => "devices",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              output        => "tln",
              version       => 20261017);

sub getConfig{return %config}

sub getShortDescr {
	return "Gets monitor Properties time stamps from Enum\\DISPLAY key (TLN)";
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();
my $reg;

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	$reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;

	my $ccs = ::getCCS($root_key);
	my $key_path = $ccs."\\Enum\\DISPLAY";
	my $key;

	if ($key = $root_key->get_subkey($key_path)) {
		my @subkeys = $key->get_list_of_subkeys();
		if (scalar @subkeys > 0) {
			foreach my $s (@subkeys) {
				my @sk = $s->get_list_of_subkeys();
				if (scalar @sk > 0) {
					foreach my $k (@sk) {
						my $name = $s->get_name();
						eval {
							$name = getName($k->get_subkey("Device Parameters")->get_value("EDID")->get_data(),$name);
						};
# get Properties\{83da6326-97a6-4088-9453-a1923f573b29}
						eval {
							getProperties($name,$k->get_subkey("Properties\\{83da6326-97a6-4088-9453-a1923f573b29}"));
						};
					}
				}
			}
		}
	}
}

#-----------------------------------------------------------
# getProperties()
# DEVPKEY_Device_InstallDate (100), DEVPKEY_Device_FirstInstallDate (101),
# DEVPKEY_Device_LastArrivalDate (102), DEVPKEY_Device_LastRemovalDate (103)
#-----------------------------------------------------------
sub getProperties {
	my $name = shift;
	my $key = shift;
	my %props = ("0064" => "Install Date",
	             "0065" => "First Install",
	             "0066" => "Last Arrival",
	             "0067" => "Last Removal");

	foreach my $p (sort keys %props) {
		eval {
			my $r = $key->get_subkey($p)->get_value("")->get_data();
			my ($t0,$t1) = unpack("VV",$r);
			my $t = ::getTime($t0,$t1);
			::rptMsg($t."|REG|||Monitor ".$props{$p}." - ".$name) if ($t > 0);
		};
	}
}

#-----------------------------------------------------------
# getName()
# Appends the monitor name and serial number from the EDID to the
# Enum\DISPLAY subkey name (ie, "DELA0D1 DELL S2722DC SN: 2WD9HD3")
#-----------------------------------------------------------
sub getName {
	my $data = shift;
	my $name = shift;

	return $name if (length($data) < 128 || substr($data,0,8) ne "\x00\xff\xff\xff\xff\xff\xff\x00");

# text is terminated by 0x0A; 13 chars with no terminator continue in the next
# descriptor with the same tag
	my %str = ();
	my %cont = ();
	foreach my $ofs (54,72,90,108) {
		next unless (unpack("v",substr($data,$ofs,2)) == 0);
		my $tag = unpack("C",substr($data,$ofs + 3,1));
		next unless ($tag == 0xFC || $tag == 0xFF);
		next if (exists $str{$tag} && !$cont{$tag});
		my $s = substr($data,$ofs + 5,13);
		my $c = ($s =~ s/[\x0a\x00].*$//s) ? 0 : 1;
		$s =~ s/[^\x20-\x7e]/\./g;
		$s =~ s/^\s+// unless ($cont{$tag});
		$s =~ s/\s+$//;
		next if ($s eq "");
		$str{$tag} .= $s;
		$cont{$tag} = $c;
	}
	my $serial = unpack("V",substr($data,12,4));

	$name .= " ".$str{0xFC} if (exists $str{0xFC});
	if (exists $str{0xFF}) {
		$name .= " SN: ".$str{0xFF};
	}
	elsif ($serial > 0) {
		$name .= " SN: ".$serial;
	}
	return $name;
}

1;
