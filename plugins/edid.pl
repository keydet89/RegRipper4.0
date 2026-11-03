#-----------------------------------------------------------
# edid.pl
# Parses the EDID data stored for each monitor beneath the Enum\DISPLAY
# key; subkeys persist for monitors that are no longer connected
#
# History
#   20261017 - created
#
# References:
#   VESA Enhanced EDID (E-EDID) Standard, Release A, Rev. 2 (EDID 1.4)
#   https://learn.microsoft.com/en-us/windows-hardware/drivers/display/overriding-monitor-edids
#   https://learn.microsoft.com/en-us/windows-hardware/drivers/install/devpkey-device-installdate
#   https://uefi.org/PNP_ID_List
#
# copyright 2026 Sujay Adkesar
# author: Sujay Adkesar, sujayadkesar2002@gmail.com
#-----------------------------------------------------------
package edid;
use strict;

my %config = (hive          => "System",
              MITRE         => "",
              category      => "devices",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              output        => "report",
              version       => 20261017);

sub getConfig{return %config}

sub getShortDescr {
	return "Parses monitor EDID data from Enum\\DISPLAY key";
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();
my $reg;

# digital interface type, byte 20 bits 3-0 (EDID 1.4)
my %iface = (1 => "DVI",
             2 => "HDMI-a",
             3 => "HDMI-b",
             4 => "MDDI",
             5 => "DisplayPort");

# extension block tags
my %ext = (0x02 => "CTA-861",
           0x10 => "VTB",
           0x40 => "DI",
           0x50 => "LS",
           0x60 => "DPVL",
           0x70 => "DisplayID",
           0xF0 => "Block Map",
           0xFF => "Manufacturer");

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	$reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;
	::logMsg("Launching edid v.".$VERSION);
	::rptMsg("edid v.".$VERSION);
	::rptMsg("(".getHive().") ".getShortDescr()."\n");

	my $ccs = ::getCCS($root_key);
	my $key_path = $ccs."\\Enum\\DISPLAY";
	my $key;

	if ($key = $root_key->get_subkey($key_path)) {

		my @subkeys = $key->get_list_of_subkeys();
		if (scalar @subkeys > 0) {
			foreach my $s (@subkeys) {
				::rptMsg($s->get_name());
				my @sk = $s->get_list_of_subkeys();
				if (scalar @sk > 0) {
					foreach my $k (@sk) {
						::rptMsg("  ".$k->get_name());
						::rptMsg(sprintf "    %-15s: %-25s","LastWrite",::format8601Date($k->get_timestamp())."Z");

						eval {
							my $x = $k->get_value("DeviceDesc")->get_data();
							::rptMsg(sprintf "    %-15s: %-30s","DeviceDesc",$x);
						};
# get Properties\{83da6326-97a6-4088-9453-a1923f573b29}
						eval {
							getProperties($k->get_subkey("Properties\\{83da6326-97a6-4088-9453-a1923f573b29}"));
						};

						my $dp;
						if ($dp = $k->get_subkey("Device Parameters")) {
							my $edid = "";
							eval {
								$edid = $dp->get_value("EDID")->get_data();
							};

							if ($edid ne "") {
								parseEDID($edid,$s->get_name());
							}
							else {
								::rptMsg("    EDID value not found.");
							}
# EDID_OVERRIDE values replace EDID blocks; each value name is a block number
							my $o;
							if ($o = $dp->get_subkey("EDID_OVERRIDE")) {
								::rptMsg("");
								::rptMsg("    EDID_OVERRIDE key found");
								::rptMsg(sprintf "    %-15s: %-25s","LastWrite",::format8601Date($o->get_timestamp())."Z");
								my @vals = $o->get_list_of_values();
								foreach my $v (@vals) {
									::rptMsg("    Override block ".$v->get_name());
									parseEDID($v->get_data(),"") if ($v->get_name() eq "0");
								}
							}
						}
						else {
							::rptMsg("    Device Parameters key not found.");
						}
						::rptMsg("");
					}
				}
			}
		}
		else {
			::rptMsg($key_path." has no subkeys.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}
	::rptMsg("Analysis Tip: Enum\\DISPLAY retains subkeys for monitors that have been connected to the system, including those");
	::rptMsg("no longer attached. The EDID is provided by the monitor, and identifies its manufacturer, model, serial number and");
	::rptMsg("date of manufacture, but contains no time stamps; use the Properties time stamps (Last Arrival, Last Removal) to");
	::rptMsg("determine when the monitor was connected. Many laptop panels and monitors report a serial number of 0; check for a");
	::rptMsg("serial string. An EDID_OVERRIDE key indicates that EDID blocks were replaced by an INF file, rather than read from");
	::rptMsg("the monitor.");
}

#-----------------------------------------------------------
# getProperties()
# DEVPKEY_Device_InstallDate (100), DEVPKEY_Device_FirstInstallDate (101),
# DEVPKEY_Device_LastArrivalDate (102), DEVPKEY_Device_LastRemovalDate (103)
#-----------------------------------------------------------
sub getProperties {
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
			::rptMsg(sprintf "    %-15s: %-25s",$props{$p},::format8601Date($t)."Z") if ($t > 0);
		};
	}
}

#-----------------------------------------------------------
# parseEDID()
# Parses the 128-byte EDID base block, and checks any extension
# blocks; $name is the Enum\DISPLAY subkey name (ie, "DELA0D1"),
# which is the manufacturer ID and product code
#-----------------------------------------------------------
sub parseEDID {
	my $data = shift;
	my $name = shift;
	my $len  = length($data);

	if ($len < 128 || substr($data,0,8) ne "\x00\xff\xff\xff\xff\xff\xff\x00") {
		::rptMsg(sprintf "    %-15s: %-30s","EDID","Not a valid EDID (".$len." bytes)");
		return;
	}
	my @b = unpack("C128",$data);

# manufacturer ID is three 5-bit letters, big endian
	my $m = ($b[8] << 8) | $b[9];
	my $mfg = chr((($m >> 10) & 0x1f) + 64).chr((($m >> 5) & 0x1f) + 64).chr(($m & 0x1f) + 64);
	my $prod = sprintf "%04X",unpack("v",substr($data,10,2));
	::rptMsg(sprintf "    %-15s: %-30s","Manufacturer",$mfg);
	::rptMsg(sprintf "    %-15s: %-30s","Product Code",$prod);

# display descriptors; 0xFC = name, 0xFF = serial string, 0xFE = data string
# text is terminated by 0x0A; 13 chars with no terminator continue in the next
# descriptor with the same tag (ie, "Nvidia Defaul" + "t Flat Panel")
	my %str = ();
	my %cont = ();
	foreach my $ofs (54,72,90,108) {
		next unless ($b[$ofs] == 0 && $b[$ofs + 1] == 0);
		my $tag = $b[$ofs + 3];
		next unless ($tag == 0xFC || $tag == 0xFF || $tag == 0xFE);
		my $s = substr($data,$ofs + 5,13);
		my $c = ($s =~ s/[\x0a\x00].*$//s) ? 0 : 1;
		$s =~ s/[^\x20-\x7e]/\./g;
		$s =~ s/^\s+// unless ($cont{$tag});
		$s =~ s/\s+$//;
		next if ($s eq "");
		if (exists $str{$tag}) {
			$str{$tag} .= ($cont{$tag}) ? $s : ", ".$s;
		}
		else {
			$str{$tag} = $s;
		}
		$cont{$tag} = $c;
	}
	::rptMsg(sprintf "    %-15s: %-30s","Monitor Name",$str{0xFC}) if (exists $str{0xFC});
	::rptMsg(sprintf "    %-15s: %-30s","Serial Number",unpack("V",substr($data,12,4)));
	::rptMsg(sprintf "    %-15s: %-30s","Serial String",$str{0xFF}) if (exists $str{0xFF});
	::rptMsg(sprintf "    %-15s: %-30s","Data String",$str{0xFE}) if (exists $str{0xFE});

# week 0xFF means the year is a model year; week 0 means not specified
	my $year = $b[17] + 1990;
	my $date;
	if ($b[16] == 0xFF) {
		$date = "Model Year ".$year;
	}
	elsif ($b[16] == 0) {
		$date = $year;
	}
	else {
		$date = "Week ".$b[16].", ".$year;
	}
	::rptMsg(sprintf "    %-15s: %-30s","Manufactured",$date);
	::rptMsg(sprintf "    %-15s: %-30s","EDID Version",$b[18].".".$b[19]);

	my $input = "Analog";
	if ($b[20] & 0x80) {
		$input = "Digital";
		if ($b[18] == 1 && $b[19] >= 4 && exists $iface{$b[20] & 0x0f}) {
			$input .= " (".$iface{$b[20] & 0x0f}.")";
		}
	}
	::rptMsg(sprintf "    %-15s: %-30s","Input",$input);

	if ($b[21] > 0 && $b[22] > 0) {
		my $diag = sqrt(($b[21] * $b[21]) + ($b[22] * $b[22]))/2.54;
		::rptMsg(sprintf "    %-15s: %-30s","Screen Size",$b[21]." x ".$b[22]." cm (".sprintf("%.1f",$diag)."\")");
	}
	else {
		::rptMsg(sprintf "    %-15s: %-30s","Screen Size","Not specified");
	}

# first detailed timing descriptor is the preferred (native) mode
	my $pclk = unpack("v",substr($data,54,2));
	if ($pclk > 0) {
		my $ha = $b[56] | (($b[58] & 0xf0) << 4);
		my $hb = $b[57] | (($b[58] & 0x0f) << 8);
		my $va = $b[59] | (($b[61] & 0xf0) << 4);
		my $vb = $b[60] | (($b[61] & 0x0f) << 8);
		my $tot = ($ha + $hb) * ($va + $vb);
		my $hz = ($tot > 0) ? ($pclk * 10000)/$tot : 0;
		my $i = ($b[71] & 0x80) ? "i" : "";
		::rptMsg(sprintf "    %-15s: %-30s","Native Mode",$ha."x".$va.$i." @ ".sprintf("%.2f",$hz)." Hz");
	}

# the value may be zero-padded beyond the declared extension blocks
	my $count = $b[126];
	my $present = int($len/128) - 1;
	$present = $count if ($present > $count);
	my @tags = ();
	foreach my $n (1..$present) {
		my $t = unpack("C",substr($data,$n * 128,1));
		push(@tags,(exists $ext{$t}) ? $ext{$t} : sprintf("0x%02X",$t));
	}
	my $e = $count;
	$e .= " declared, ".$present." in value" if ($present != $count);
	$e .= " (".join(", ",@tags).")" if (scalar @tags > 0);
	::rptMsg(sprintf "    %-15s: %-30s","Extensions",$e);

# each 128-byte block sums to 0 (mod 256)
	my @bad = ();
	foreach my $n (0..$present) {
		push(@bad,$n) if (unpack("%32C*",substr($data,$n * 128,128)) % 256);
	}
	::rptMsg(sprintf "    %-15s: %-30s","Checksum",(scalar @bad == 0) ? "OK" : "Bad (block ".join(", ",@bad).")");

	if ($name ne "" && uc($name) ne $mfg.$prod) {
		::rptMsg("    Note: EDID manufacturer/product code (".$mfg.$prod.") does not match key name");
	}
}

1;
