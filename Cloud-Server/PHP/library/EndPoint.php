<?php
// AngelsGateLite V.1 EndPoint class library by NIMIX3
// https://github.com/nimix3/AngelsGateLite
// 2018-2019

class GlobalApi
{
	public $AngelsGate;
	public $Config;
	public $SQL;
	
	public function __construct($ConfFile='config/config.php')
	{
		try{
			if(isset($ConfFile) and !empty($ConfFile))
			{
				if(file_exists($ConfFile))
				{
					include($ConfFile);
					$this->Config = $Configurations;
					unset($Configurations);
				}
				else
				{
					include('config/config.php');
					$this->Config = $Configurations;
					unset($Configurations);
				}
			}
			else
				exit('ERROR_SERVER_FATAL');
			$this->AngelsGate = new AngelsGate();
			$this->SQL = new SQLi($this->Config);
			return $this;
		}
		catch(Exception $e) {
			$this->AngelsGate->Output('ERROR_SERVER_FATAL','_GLOBAL_',true);
		}
	}
	
	public function checkUpdate()
	{
		if(isset($this->AngelsGate->Data) and !empty($this->AngelsGate->Data))
		{
			try{
				$Latest = '1.0.0';
				@ $Ver = $this->AngelsGate->Data['version'];
				if(!isset($Ver) or empty($Ver))
					$this->AngelsGate->Output('ERROR_INPUT_EMPTY',$this->AngelsGate->Deviceid,true);
				if($Ver == $Latest)
				{
					$this->AngelsGate->Output('NOTICE_UPDATE_NOTEXIST',$this->AngelsGate->Deviceid,true);
				}
				else
				{
					$this->AngelsGate->Output('NOTICE_UPDATE_EXIST',$this->AngelsGate->Deviceid,true);
				}
			}
			catch(Exception $e)
			{
				$this->AngelsGate->Output('ERROR_SERVER_EXCEPTION',$this->AngelsGate->Deviceid,true);
			}
		}
		else
		{
			$this->AngelsGate->Output('ERROR_INPUT_EMPTY',$this->AngelsGate->Deviceid,true);
		}
	}
	
	public function Signal()
	{
		try{
			//Signal only have Token,Addition but not everything\\
			$SQL = $this->SQL;
			if($SQL->InitDB())
			{
				$resx = $SQL->SelectDBsecure('*','HashTable','session','=','?',array($this->AngelsGate->Addition));
				if(isset($resx[0]) and !empty($resx[0]))
				{
					$SQL->CloseDB();
					$this->AngelsGate->RawOutput('99',true);
				}
				else
				{
					$SQL->CloseDB();
					$this->AngelsGate->RawOutput('25',true);
				}
			}
			else
			{
				$this->AngelsGate->RawOutput('-98',true);
			}
		}
		catch(Exception $e)
		{
			$this->AngelsGate->RawOutput('-99',true);
		}
	}
	
	public function getServerTime()
	{
		$this->AngelsGate->SyncTime();
	}
}
?>