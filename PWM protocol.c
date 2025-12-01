void ChkLanCommand(int server_no, int client_id)
{
	char str[80], sub[40];
	int i;
	uint32_t d;
	
	m_LanWdtTime = 0;
	m_ServerNO = server_no, m_ClientID = client_id;

	if (strncmp((char *)m_LanCommand, "R000?", 5) == 0) {	// raw data
		m_LanTxLedTime = LED_TIME;
		union {
			unsigned char b[4];
			float d;
		}fd1, fd2;
		
		fd1.d = m_Direct;
		fd2.d = m_Speed;
		sprintf(str, "R000:%c%c%c%c%c%c%c%c\r\n", fd1.b[0], fd1.b[1], fd1.b[2], fd1.b[3],
			fd2.b[0], fd2.b[1], fd2.b[2], fd2.b[3]);
		tcp_write(mp_ClientTcpPcb[server_no][client_id], (void *)str, 15, 1);	// strlen 사용 불가 (m_Buf에 0x00 이 있을 수 있음)
		tcp_output(mp_ClientTcpPcb[server_no][client_id]);
	}
	else if (strncmp((char *)m_LanCommand, "R001?", 5) == 0) {	// 1min data (240)
		m_LanTxLedTime = LED_TIME;
		
		uint8_t ret, mis_cnt=5;
		float direct, speed;
		float old_direct=0.0f, old_speed=0.0f;
		RTC_DateTypeDef date;
		RTC_TimeTypeDef time;
	
		strncpy(sub, (char *)&m_LanCommand+5, 8);
		date.Year = 20;
		str[0] = sub[0], str[1] = sub[1], str[2] = '\0';	date.Month = atoi(str);
		str[0] = sub[2], str[1] = sub[3], str[2] = '\0';	date.Date = atoi(str);
		str[0] = sub[4], str[1] = sub[5], str[2] = '\0';	time.Hours = atoi(str);
		str[0] = sub[6], str[1] = sub[7], str[2] = '\0';	time.Minutes = atoi(str);
		
		m_AppBuf[0] = 'R', m_AppBuf[1] = '0', m_AppBuf[2] = '0', m_AppBuf[3] = '1', m_AppBuf[4] = ':';
		m_AppBuf[5] = date.Month, m_AppBuf[6] = date.Date, m_AppBuf[7] = time.Hours, m_AppBuf[8] = time.Minutes;
		
		for (i=0;i<60;i++) {
			time.Seconds = i;
			ret = NorFlashRead(date, time);
			direct = m_ReadDirect * 10.0f, speed = m_ReadSpeed * 10.0f;
			
			if (ret == 0xff) {
				if (++mis_cnt < 5) {
					direct = old_direct;
					speed = old_speed;
				}
				else {
					mis_cnt = 5;
				}
			}
			else {
				old_direct = direct;
				old_speed = speed;
				mis_cnt = 0;
			}
		
			m_AppBuf[i*4+9] = (uint16_t)direct>>8,	m_AppBuf[i*4+10] = (uint16_t)direct&0xff;
			m_AppBuf[i*4+11] = (uint16_t)speed>>8,	m_AppBuf[i*4+12] = (uint16_t)speed&0xff;
		}
		tcp_write(mp_ClientTcpPcb[server_no][client_id], (void *)m_AppBuf, 249, 1);	// strlen 사용 불가 (m_Buf에 0x00 이 있을 수 있음)
		tcp_output(mp_ClientTcpPcb[server_no][client_id]);
	}
	else if (strncmp((char *)m_LanCommand, "R002?", 5) == 0) {	// 5min data (1200)
		m_LanTxLedTime = LED_TIME;
		
		uint8_t ret, mis_cnt=5, org_min;
		float direct, speed;
		float old_direct=0.0f, old_speed=0.0f;
		RTC_DateTypeDef date;
		RTC_TimeTypeDef time;
	
		strncpy(sub, (char *)&m_LanCommand+5, 8);
		date.Year = 20;
		str[0] = sub[0], str[1] = sub[1], str[2] = '\0';	date.Month = atoi(str);
		str[0] = sub[2], str[1] = sub[3], str[2] = '\0';	date.Date = atoi(str);
		str[0] = sub[4], str[1] = sub[5], str[2] = '\0';	time.Hours = atoi(str);
		str[0] = sub[6], str[1] = sub[7], str[2] = '\0';	time.Minutes = org_min = atoi(str)/5*5;
		
		m_AppBuf[0] = 'R', m_AppBuf[1] = '0', m_AppBuf[2] = '0', m_AppBuf[3] = '2', m_AppBuf[4] = ':';
		m_AppBuf[5] = date.Month, m_AppBuf[6] = date.Date, m_AppBuf[7] = time.Hours, m_AppBuf[8] = time.Minutes;
		
		for (i=0;i<300;i++) {
			time.Seconds = i%60;
			time.Minutes = org_min + i/60;
			ret = NorFlashRead(date, time);
			direct = m_ReadDirect * 10.0f, speed = m_ReadSpeed * 10.0f;
			
			if (ret == 0xff) {
				if (++mis_cnt < 5) {
					direct = old_direct;
					speed = old_speed;
				}
				else {
					mis_cnt = 5;
				}
			}
			else {
				old_direct = direct;
				old_speed = speed;
				mis_cnt = 0;
			}
		
			m_AppBuf[i*4+9] = (uint16_t)direct>>8,	m_AppBuf[i*4+10] = (uint16_t)direct&0xff;
			m_AppBuf[i*4+11] = (uint16_t)speed>>8,	m_AppBuf[i*4+12] = (uint16_t)speed&0xff;
		}
		tcp_write(mp_ClientTcpPcb[server_no][client_id], (void *)m_AppBuf, 1209, 1);	// strlen 사용 불가 (m_Buf에 0x00 이 있을 수 있음)
		tcp_output(mp_ClientTcpPcb[server_no][client_id]);
	}
	
	
	else if (strncmp((char *)m_LanCommand, "FLS?", 4) == 0) {
		m_LanTxLedTime = LED_TIME;
		
		str[0] = 'F', str[1] = 'L', str[2] = 'S', str[3] = ':';
		str[4] = m_LanCommand[4];
		U32toChar(&str[5], ReadFLASH(m_LanCommand[4]));
		
		tcp_write(mp_ClientTcpPcb[server_no][client_id], (void *)str, 9, 1);	// strlen 사용 불가 (m_Buf에 0x00 이 있을 수 있음)
		tcp_output(mp_ClientTcpPcb[server_no][client_id]);
	}
	else if (strncmp((char *)m_LanCommand, "FLS:", 4) == 0) {
		m_LanTxLedTime = LED_TIME;
		memcpy(sub, (char *)&m_LanCommand+4, 5);	// ascii가 아닌 bin data라서 strncpy 사용 불가
		
		if (sub[0] < MAX_FLASH)	m_Flash[sub[0]] = ChartoU32(&sub[1]);
		
		tcp_write(mp_ClientTcpPcb[server_no][client_id], (void *)m_LanCommand, 9, 1);	// strlen 사용 불가 (m_Buf에 0x00 이 있을 수 있음)
		tcp_output(mp_ClientTcpPcb[server_no][client_id]);
		
		HAL_IWDG_Refresh(&hiwdg);
		d = ChartoU32(&sub[1]);
		m_CRC = CRC16((unsigned char *)(&d), 4);
		WriteFLASH(sub[0], d);
		HAL_IWDG_Refresh(&hiwdg);
		
		if (sub[0] == FLS_DHCP || sub[0] == FLS_IP || sub[0] == FLS_NETMASK)	m_System.flag.NET_RELOAD_FLAG = 1;
		else if (sub[0] == FLS_BAUD)	SetBaudrate();
	}
	else if (strncmp((char *)m_LanCommand, "CPU FLS?", 8) == 0) {
		m_LanTxLedTime = LED_TIME;
		memcpy(sub, (char *)&m_LanCommand+8, 4);	// ascii가 아닌 bin data라서 strncpy 사용 불가
		
		uint32_t addr = ChartoU32(sub);
		uint32_t dat = *(__IO uint32_t *)addr;
		
		sprintf(str, "CPU FLS:%08X,%08X\r\n", addr, dat);
		tcp_write(mp_ClientTcpPcb[server_no][client_id], (void *)str, strlen(str), 1);
		tcp_output(mp_ClientTcpPcb[server_no][client_id]);
	}
	else if (strncmp((char *)m_LanCommand, "SET?", 4) == 0) {	// read settings
		m_LanTxLedTime = LED_TIME;
		str[0] = 'S', str[1] = 'E', str[2] = 'T', str[3] = ':';

		U32toChar(&str[4], m_Flash[FLS_VER]);
		U32toChar(&str[8], m_Flash[FLS_PASS]);
		str[12] = m_Flash[FLS_DHCP];
		if (m_Flash[FLS_DHCP]) {
			U32toChar(&str[13], (u32_t)gnetif.gw.addr);
			U32toChar(&str[17], (u32_t)gnetif.netmask.addr);
			U32toChar(&str[21], (u32_t)gnetif.ip_addr.addr);
		}
		else {
			U32toChar(&str[13], m_Flash[FLS_GATEWAY]);
			U32toChar(&str[17], m_Flash[FLS_NETMASK]);
			U32toChar(&str[21], m_Flash[FLS_IP]);
		}
		U32toChar(&str[25], m_Flash[FLS_TIME_IP]);
		str[29] = m_Flash[FLS_PROTOCOL];
		str[30] = m_Flash[FLS_RS232];
		str[31] = m_Flash[FLS_ID];
		str[32] = m_Flash[FLS_BAUD];
		
		tcp_write(mp_ClientTcpPcb[server_no][client_id], (void *)str, 33, 1);	// strlen 사용 불가 (m_Buf에 0x00 이 있을 수 있음)
		tcp_output(mp_ClientTcpPcb[server_no][client_id]);
	}
	else if (strncmp((char *)m_LanCommand, "SET:", 4) == 0) {	// write settings
		m_LanTxLedTime = LED_TIME;
		memcpy(sub, (char *)&m_LanCommand+4, 29);
		
		m_Flash[FLS_VER] = ChartoU32(&sub[0]);
		m_Flash[FLS_PASS] = ChartoU32(&sub[4]);
		m_Flash[FLS_DHCP] = sub[8];
		m_Flash[FLS_GATEWAY] = ChartoU32(&sub[9]);
		m_Flash[FLS_NETMASK] = ChartoU32(&sub[13]);
		m_Flash[FLS_IP] = ChartoU32(&sub[17]);
		m_Flash[FLS_TIME_IP] = ChartoU32(&sub[21]);
		m_Flash[FLS_PROTOCOL] = sub[25];
		m_Flash[FLS_RS232] = sub[26];
		m_Flash[FLS_ID] = sub[27];
		m_Flash[FLS_BAUD] = sub[28];

		sprintf(str, "SET:OK\r\n");
		tcp_write(mp_ClientTcpPcb[server_no][client_id], (void *)str, strlen(str), 1);
		tcp_output(mp_ClientTcpPcb[server_no][client_id]);
		
		for (i=0;i<FLS_CRC;i++) {
			WDR();
			m_CRC = CRC16((unsigned char *)(m_Flash + i), 4);
			WriteFLASH(i, m_Flash[i]);
		}
		WriteFlshCRC(0);
		BackupFlash();
		
		m_System.flag.NET_RELOAD_FLAG = 1;
		SetBaudrate();
	}
	else if (strncmp((char *)m_LanCommand, "DATE?", 5) == 0) {	// read date time
		m_LanTxLedTime = LED_TIME;
		sprintf(str, "DATE:20%02d.%2d.%2d %2d:%2d:%2d\r\n", sDate.Year, sDate.Month, sDate.Date
			, sTime.Hours, sTime.Minutes, sTime.Seconds);
		tcp_write(mp_ClientTcpPcb[server_no][client_id], (void *)str, strlen(str), 1);
		tcp_output(mp_ClientTcpPcb[server_no][client_id]);
	}
	else if (strncmp((char *)m_LanCommand, "DATE:", 5) == 0) {	// set date
		m_LanTxLedTime = LED_TIME;
		strncpy(sub, (char *)&m_LanCommand+5, 20);	sub[20] = '\0';
		if (strlen(sub) == 19) {
			sprintf(str, "%c%c", sub[2], sub[3]);	sDate.Year = atoi(str);
			sprintf(str, "%c%c", sub[5], sub[6]);	sDate.Month = atoi(str);
			sprintf(str, "%c%c", sub[8], sub[9]);	sDate.Date = atoi(str);
			sprintf(str, "%c%c", sub[11], sub[12]);	sTime.Hours = atoi(str);
			sprintf(str, "%c%c", sub[14], sub[15]);	sTime.Minutes = atoi(str);
			sprintf(str, "%c%c", sub[17], sub[18]);	sTime.Seconds = atoi(str);
			//WriteDS3231(sDate, sTime);
			HAL_RTC_SetDate(&hrtc, &sDate, FORMAT_BIN);
			HAL_RTC_SetTime(&hrtc, &sTime, FORMAT_BIN);
			sprintf(str, "DATE:OK\r\n");
		}
		else {
			sprintf(str, "DATE:NG\r\n");
		}
		tcp_write(mp_ClientTcpPcb[server_no][client_id], (void *)str, strlen(str), 1);
		tcp_output(mp_ClientTcpPcb[server_no][client_id]);
	}
	else if (strncmp((char *)m_LanCommand, "IP:", 3) == 0) {	// 사용 안하고 FLS: 명령어 사용
		m_LanTxLedTime = LED_TIME;
		strncpy(sub, (char *)&m_LanCommand+3, 8);
		sub[8] = NULL;
		
		m_Flash[FLS_IP] = (uint32_t)strtoul(sub, NULL, 16);
		
		sprintf(str, "IP:%08X\r\n", m_Flash[FLS_IP]);
		tcp_write(mp_ClientTcpPcb[server_no][client_id], (void *)str, strlen(str), 1);
		tcp_output(mp_ClientTcpPcb[server_no][client_id]);
		osDelay(100);
		
		m_CRC = CRC16((unsigned char *)(m_Flash + FLS_IP), 4);
		WriteFLASH(FLS_IP, m_Flash[FLS_IP]);
		m_System.flag.NET_RELOAD_FLAG = 1;
	}
	else if (strncmp((char *)m_LanCommand, "MAC?", 4) == 0) {	// read mac address
		m_LanTxLedTime = LED_TIME;
		sprintf(str, "MAC:%02X%02X%02X%02X%02X%02X\r\n", user_MACAddr[0], user_MACAddr[1]
			, user_MACAddr[2], user_MACAddr[3], user_MACAddr[4], user_MACAddr[5]);
		tcp_write(mp_ClientTcpPcb[server_no][client_id], (void *)str, strlen(str), 1);
		tcp_output(mp_ClientTcpPcb[server_no][client_id]);
	}
	else if (strncmp((char *)m_LanCommand, "UID?", 4) == 0) {	// MCU ID
		m_LanTxLedTime = LED_TIME;
		uint32_t UID[3];
		UID[0] = *(__IO uint32_t *)UID_BASE;
		UID[1] = *(__IO uint32_t *)(UID_BASE + 4);
		UID[2] = *(__IO uint32_t *)(UID_BASE + 8);
		sprintf(str, "UID:%08X%08X%08X\r\n", UID[0], UID[1], UID[2]);
		tcp_write(mp_ClientTcpPcb[server_no][client_id], (void *)str, strlen(str), 1);
		tcp_output(mp_ClientTcpPcb[server_no][client_id]);
	}
	else if (strncmp((char *)m_LanCommand, "VER?", 4) == 0) {
		m_LanTxLedTime = LED_TIME;
		sprintf(str, "VER:%s,%s,%s,%s\r\n", MODEL, VERSION_STR, __DATE__, __TIME__);
		tcp_write(mp_ClientTcpPcb[server_no][client_id], (void *)str, strlen(str), 1);
		tcp_output(mp_ClientTcpPcb[server_no][client_id]);
	}
	else if (strncmp((char *)m_LanCommand, "BOOT VER?", 9) == 0) {
		m_LanTxLedTime = LED_TIME;
		sprintf(str, "BOOT VER:%s\r\n", m_BootVersionStr);
		tcp_write(mp_ClientTcpPcb[server_no][client_id], (void *)str, strlen(str), 1);
		tcp_output(mp_ClientTcpPcb[server_no][client_id]);
	}
	else if (strncmp((char *)m_LanCommand, "MODEL?", 6) == 0) {
		m_LanTxLedTime = LED_TIME;
		sprintf(str, "MODEL:%s,%s\r\n", MODEL, VERSION_STR);
		tcp_write(mp_ClientTcpPcb[server_no][client_id], (void *)str, strlen(str), 1);
		tcp_output(mp_ClientTcpPcb[server_no][client_id]);
	}
	else {
		m_LanTxLedTime = LED_TIME;
		sprintf(str, "Command not allowed.\r\n");
		tcp_write(mp_ClientTcpPcb[server_no][client_id], (void *)str, strlen((char *)str), 1);
		tcp_output(mp_ClientTcpPcb[server_no][client_id]);
	}
}
