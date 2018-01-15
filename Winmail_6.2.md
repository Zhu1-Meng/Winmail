<h1>Winmail 6.2 Remote Code Execution Vulnerability</h1>

----------

## 0x01 Description ##
Winmail Server 6.2 allows remote code execution by authenticated users who leverage directory traversal in a netdisk.php copy\_folder\_file call to move shell.php file from the FTP folder into a web folder.

## 0x02 Vendor of Product ##
Magicwinmail, Winmail Server <=6.2

## 0x03 Discoverer ##
Wfox, Shanghai kuangchuang information technology co LTD

## 0x04 Vulnerability details ##
/www/main.php<br>

	switch($act){//line 166
		...
		case 'netdisk'://line 269
			include('../operation/netdisk.php');
			break;	
	}

follow "/operation/netdisk.php"

	//line 351-427
	case 'copy':
		$count = 0;
		$size = 0;
		$bRet = false;
		
		$dfolder = base64_decode($toftpfolder);
		if ($ftphandle->folder_is_safe($dfolder) && $ftpfolder != $dfolder){
			if ($filename == '') {
				$pagesize = $session_value['preferences']['recodeperpage'];
				for ($i = 0; $i < $pagesize; $i++){
					$item = ${'item_'.$i};
					if ($item == '')
						continue;
						
					$filename = base64_decode($item);
					if ($ftphandle->folder_is_safe($filename)){
						$ftpfile = $ftpfolder;
						if (substr($ftpfile, -1) != '/')
							$ftpfile .= '/';
						$ftpfile .= $filename;
		
						$destfile = $dfolder;
						if (substr($destfile, -1) != '/')
							$destfile .= '/';
						$destfile .= $filename;
		
						if ($ftpfile != $destfile){
							if ($ftphandle->copy_folder_file($ftpfile, $destfile)) {
								$bRet = true;
				
								$count += $info['count'];
								$size += $info['size'];
							}
						}
					}
				}
			}
			else {
				$filename = base64_decode($filename);
				if ($ftphandle->folder_is_safe($filename)){
					$ftpfile = $ftpfolder;
					if (substr($ftpfile, -1) != '/')
						$ftpfile .= '/';
					$ftpfile .= $filename;
	
					$destfile = $dfolder;
					if (substr($destfile, -1) != '/')
						$destfile .= '/';
					$destfile .= $filename;
	
					if ($ftpfile != $destfile){
						if ($ftphandle->copy_folder_file($ftpfile, $destfile)) {
							$bRet = true;
			
							$count += $info['count'];
							$size += $info['size'];
						}
					}
				}
			}
		}
		
		$smarty->assign('ReadFile', 'true');
		$smarty->assign('ReadFolder', 'false');
		if ($bRet) {
			$result = 0;
			
			$ftphandle->set_ftp_quota($size, $count, '+');
		}
		else {
			$result = 1;
		}
			
		$smarty->assign('errCode', $result);
		
		$templatename = 'netdisk-results.htm';
		break;

follow function copy\_folder\_file in /inc/class.ftpfolder.php

	//line 299-339
	function copy_folder_file($oldfolder, $newfolder) {
		if (strcasecmp($oldfolder, $newfolder) == 0)
			return false;

		$info = array();
		$info['count'] = 0;
		$info['size'] = 0;

		$oldpath = $this->ftp_home_directory.$oldfolder;
		$newpath = $this->ftp_home_directory.$newfolder;
		
		if (is_dir($oldpath)) {
			if (!file_exists($newpath))
				@mkdir($newpath);
				
			$dh = opendir($oldpath);
			if ($dh){
				while($file = readdir($dh)) {
					if ($file == '.' || $file == '..')
						continue;
					
					$oldfullfolder = $oldfolder.'/'.$file;
					$newfullfolder = $newfolder.'/'.$file;
					
					$subinfo = $this->copy_folder_file($oldfullfolder, $newfullfolder);
					if ($subinfo != false) {
						$info['count'] += $subinfo['count'];
						$info['size'] += $subinfo['size'];
					}
				}
			}
		}
		else {
			if (@copy($oldpath, $newpath)) {
				$info['count'] = 1;
				$info['size'] = filesize($newpath);
			}
		}
		
		return $info;
	}


## 0x05 Exploit ##
After web login authentication, copy the file through netdisk(copy) and finally "copy\_folder\_file".<br>
When "copy\_folder\_file" is passed a directory path, the directory is traversed.

1.Visit the netdisk page,create a new directory "webmail",then create a new directory "www",enter "/webmail/www",upload shell.php<br>
2.Into the directory "/webmail",copy file，Data：toftpfolder=Ly4u&item_0=Ly4u<br>
3.function "copy\_folder\_file"  copy "/webmail/.." traversal to "/../.."<br>
4.Finally, shell.php is copied into the web directory, executing malicious code
