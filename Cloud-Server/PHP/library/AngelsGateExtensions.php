<?php
// AngelsGateLite V.1 Extension class library by NIMIX3
// https://github.com/nimix3/AngelsGateLite
// 2018-2019

trait HashController
{
	public function HashChecker($SQL,$Ssalt,$IP,$Deviceid,$timelimit=86400)
	{
		if(!isset($SQL,$Ssalt,$Deviceid,$IP) or empty($SQL) or empty($Ssalt) or empty($Deviceid) or empty($IP))
			return false;
		if($SQL->InitDB())
		{
			$Deviceid = $SQL->SecureDBQuery($Deviceid,true);
			$Ssalt = $SQL->SecureDBQuery($Ssalt,true);
			$IP = $SQL->SecureDBQuery($IP,true);
			$resx = $SQL->SelectDBsecure('*','HashTable','session','=','? AND `ssalt` = ?',array($Deviceid,$Ssalt));
			if(isset($resx[0]) and !empty($resx[0]))
			{
				if(intval($resx[0]['time']) + intval($timelimit) >= time())
				{
					return false;
				}
				else
				{
					$SQL->UpdateDBsecure('HashTable','session','=','? AND `ssalt` = ?',array($Deviceid,$Ssalt),array('time'=>time(),'ip'=>$IP),1);
					return true;
				}
			}
			else
			{
				$SQL->InsertDBsecure('HashTable',array('ssalt'=>$Ssalt,'time'=>time(),'ip'=>$IP,'session'=>$Deviceid));
				return true;
			}
		}
		else
		{
			return false;
		}
	}
}

?>