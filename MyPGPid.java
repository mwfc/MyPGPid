/*
 * MyPGPid applet
 * (C) 2013 Diego 'NdK' Zuccato
 * Released under GNU Public Licence (GPL)
 * Package AID: 0xF9:0x4D:0x79:0x50:0x47:0x50:0x69:0x64:0x00:0x00 (F9 'MyPGPid' 00 00)
 * Applet AID:  0xF9:0x4D:0x79:0x50:0x47:0x50:0x69:0x64:0x30:0x31 (F9 'MyPGPid01')
 */

package MyPGPid;

/*
 * Imported packages
 */
// specific import for Javacard API access
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;



public class MyPGPid extends javacard.framework.Applet
{
	// Odd high nibble in CLA means 'chaining'
	final static byte CLA_CARD_TEST               = (byte) 0xE0;

	// Commands OP 2.01 CLAs according to 7.4 
	// TODO find speaking names
	final static byte CLA_00						= (byte) 0x00;
	final static byte CLA_0C						= (byte) 0x0C;
	final static byte CLA_10						= (byte) 0x10;
	final static byte CLA_1C						= (byte) 0x1C;

	// INS cannot be odd
	final static byte INS_CARD_READ_POLICY           = (byte) 0x70;
	final static byte INS_CARD_KEY_PUSH              = (byte) 0x72;
	// final static byte INS_CARD_KEY_SELECT           = (byte) 0x7;
	final static byte INS_PIN_VERIFY				= (byte) 0x20;
	final static byte INS_PIN_RESET_RETRY_COUNTER	= (byte) 0x2C;
	final static byte INS_PIN_CHANGE_REFERENCE_DATA	= (byte) 0x24;
	final static byte INS_PUT_DATA_A				= (byte) 0xDA;
	final static byte INS_PUT_DATA_B				= (byte) 0xDB;
	final static byte INS_GENERATE_ASYMMETRIC_KEY_PAIR	= (byte) 0x47;
	final static byte INS_PERFORM_SECURITY_OPERATION	= (byte) 0x2A;
	final static byte INS_INTERNAL_AUTHENTICATE		= (byte) 0x88;
	final static byte INS_GET_RESPONSE				= (byte) 0xC0;
	final static byte INS_TERMINATE_DF				= (byte) 0x44;
	final static byte INS_ACTIVATE_FILE				= (byte) 0xE6;

	// Status codes
	final static short SW_SECURITY_STATUS_NOT_SATISFIED	= (short) 0x6982;
	final static short SW_AUTHENTICATION_BLOCKED		= (short) 0x6983;
	final static short SW_INS_NOT_SUPPORTED				= (short) 0x6D00;


	final static short RESP_TEST						= (short) 0x7777;



	// JCOP
	//    final static byte  DEF_ALG = KeyPair.ALG_RSA_CRT;
	//    final static short DEF_LEN = (short)2048;	// bits
	//    final static short DEF_CAKEYTYPE = KeyBuilder.TYPE_RSA_PUBLIC;

	// G+D SmartCafé Expert
	//    final static byte  DEF_ALG = KeyPair.ALG_RSA;
	//    final static short DEF_LEN = (short)2048;	// bits
	//    final static byte  DEF_CAKEYTYPE = KeyBuilder.TYPE_RSA_PUBLIC;

	// *** Extended function support
	private KeyPair[]	m_keyPair = null;	// Keeps all key pairs
	private byte[]	m_transferBuffer = null;
	private byte	m_extFlag = (byte)0;// Using extensions
	private byte	m_currEncKey = 1;
	private byte	m_nPins = 2;
	private short	m_maxKeys = 3;	// SIG,DEC,AUT
	private short	m_bSize = 0;	// buffer size
	private boolean	m_separateAuth = false;// Use different AUT key/PIN for RFID
	private byte	m_oobAuth = 0;	// Require OOB auth for SIG key
	private boolean	m_CAKeyIsSet = false; // True when CA key is set
	private PublicKey	m_CAKey = null;

	// PIN handling
	// see OpenPGP Specification 4.2
	// Min lenght pw1 6, pw3 8
	// UTF-8 encoding! (It does not matter on a byte level, but length varies)
	// TODO FIX length, UTF-8 is from 1 - 6 Byte, therefore 6-36 byte PW1_MIN
	// TODO implement max length Dataobject. Beware of 1-6 Byte per UTF-8 char!
	// TODO Reset Code Useful?

	private OwnerPIN pw1; // User-password
	private OwnerPIN pw3; // Admin-password
	private byte pw1Length;
	private byte pw3Length;

	final static byte  PW_MAXTRY 		= (byte) 3;
	final static byte  PW1_MINLENGTH	= (byte) 6;
	final static byte  PW1_MAXLENGTH	= (byte) 0x7F;
	final static byte  PW3_MINLENGTH 	= (byte) 8;
	final static byte  PW3_MAXLENGTH	= (byte) 0x7F;


	final static byte[] PW1_DEFAULT = {(byte)0x31, (byte)0x32, (byte)0x33, (byte)0x34, (byte)0x35, (byte)0x36 };
	final static byte[] PW3_DEFAULT = {(byte)0x31, (byte)0x32, (byte)0x33, (byte)0x34, (byte)0x35, (byte)0x36, (byte)0x37, (byte)0x38 };


	/**
	 * MyPGPid default constructor
	 * Only this class's install method should create the applet object.
	 */
	protected MyPGPid(byte[] buffer, short offset, byte length)
	{

		// Pre-allocate default PINs
		// PW1= 123456  PW3=12345678
		// see OP2.0.1 4.2

		pw1 = new OwnerPIN(PW_MAXTRY, PW1_MAXLENGTH);
		pw3 = new OwnerPIN(PW_MAXTRY, PW3_MAXLENGTH );

		pw1.update(PW1_DEFAULT, (byte) 0, PW1_MINLENGTH);
		pw1Length = (byte) PW1_DEFAULT.length;
		pw3.update(PW3_DEFAULT, (byte) 0, PW3_MINLENGTH);
		pw3Length = (byte) PW3_DEFAULT.length;

		register();
	}

	/**
	 * Method installing the applet.
	 * @param bArray the array constaining installation parameters
	 * @param bOffset the starting offset in bArray
	 * @param bLength the length in bytes of the data parameter in bArray
	 */
	public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException
	{
		/* applet  instance creation */
		new MyPGPid(bArray, bOffset, (byte)bLength );
	}

	/**
	 * Select method returns true if applet selection is supported.
	 * @return boolean status of selection.
	 */
	public boolean select()
	{
		// TODO do we need select actions?
		return true;
	}

	/**
	 * Deselect method called by the system in the deselection process.
	 */
	public void deselect()
	{
		// <PUT YOUR DESELECTION ACTION HERE>
		return;
	}

	/**
	 * Method processing an incoming APDU.
	 * @see APDU
	 * @param apdu the incoming APDU
	 * @exception ISOException with the response bytes defined by ISO 7816-4
	 */
	public void process(APDU apdu) throws ISOException
	{
		short	lc;
		boolean verified = false;

		// ignore the applet select command dispatched to the process
		if (selectingApplet())
			return;

		// get the APDU buffer
		byte[] apduBuffer = apdu.getBuffer();


		// Testing Correct CLAs
		if (!((apduBuffer[ISO7816.OFFSET_CLA] == CLA_00) || (apduBuffer[ISO7816.OFFSET_CLA] == CLA_0C) 
				|| (apduBuffer[ISO7816.OFFSET_CLA] == CLA_10) || (apduBuffer[ISO7816.OFFSET_CLA] == CLA_1C))) {
			// NOT SUPPORTED CLA
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}

		switch ( apduBuffer[ISO7816.OFFSET_INS]){
		case INS_PIN_VERIFY:
			// ONLY CLA 00,0C
			if (!((apduBuffer[ISO7816.OFFSET_CLA] == CLA_00) || (apduBuffer[ISO7816.OFFSET_CLA] == CLA_0C))){
				// NOT SUPPORTED CLA 0x10 OR 0x1C
				ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
			}

			// P1 check, must be 0x00
			if (!(apduBuffer[ISO7816.OFFSET_P1] == 0x00))
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);

			// length of provided password
			lc = apdu.setIncomingAndReceive();

			switch(apduBuffer[ISO7816.OFFSET_P2]) {
			case (byte) 0x81:
				// Only for PSO:CDS, PW1
				if (pw1.getTriesRemaining() == (byte) 0){
					ISOException.throwIt(SW_AUTHENTICATION_BLOCKED);
				}

			verified = pw1.check(apduBuffer, (short) ISO7816.OFFSET_CDATA, (byte) lc);

			break;
			case (byte) 0x82:
				// PW1 for other functions
				if (pw1.getTriesRemaining() == (byte) 0x00){
					ISOException.throwIt(SW_AUTHENTICATION_BLOCKED);
				}
			verified = pw1.check(apduBuffer, (short) ISO7816.OFFSET_CDATA, (byte) lc);
			break;
			case (byte) 0x83:
				// PW3
				if (pw3.getTriesRemaining() == (byte) 0x00){
					ISOException.throwIt(SW_AUTHENTICATION_BLOCKED);
				}
			verified = pw3.check(apduBuffer, (short) ISO7816.OFFSET_CDATA, (byte) lc);
			break;
			default:
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}


			if(!verified)
				ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
			return;

		case INS_PIN_CHANGE_REFERENCE_DATA:
			// CLAs 0x00 0x0C 0x1C 0x10 allowed
			if (apduBuffer[ISO7816.OFFSET_INS] != 0x24){
				ISOException.throwIt(SW_INS_NOT_SUPPORTED);
			}

			lc = apdu.setIncomingAndReceive();

			if (apduBuffer[ISO7816.OFFSET_P1] != 0x00){
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			}


			byte inputPWLength;
			switch(apduBuffer[ISO7816.OFFSET_P2]) {	
			// Change PW1 
			// We MUST use check method in all cases, to count wrong password counter
			case (byte) 0x81:
				if (lc < pw1Length){
					inputPWLength = (byte) lc;
				} else {
					inputPWLength = pw1Length;			
				}

			if (!(pw1.check(apduBuffer, ISO7816.OFFSET_CDATA, inputPWLength))){
				ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
			}

			// PINs can only be byte size long, 0-127 
			// PINs can have a length of MIN - 127 - UTF8 loss -> MIN - (21..127)

			if ((lc - pw1Length ) < PW1_MINLENGTH ){
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			}

			pw1.update(apduBuffer, (short) (ISO7816.OFFSET_CDATA + pw1Length), (byte)(lc-pw1Length));

			break;
			// Change PW3 
			// We MUST use check method in all cases, to count wrong password counter
			case (byte) 0x83:
				if (lc < pw3Length){
					inputPWLength = (byte) lc;
				} else {
					inputPWLength = pw3Length;			
				}


			if (!(pw3.check(apduBuffer, ISO7816.OFFSET_CDATA, inputPWLength))){
				ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
			}

			// PINs can only be byte size long, 0-127 
			// PINs can have a length of MIN - 127 - UTF8 loss -> MIN - (21..127)

			if ((lc - pw3Length ) < PW3_MINLENGTH ){
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			}

			pw3.update(apduBuffer, (short) (ISO7816.OFFSET_CDATA + pw3Length), (byte)(lc-pw3Length));

			break;

			default:
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);

			}
			return;
		}
	}
}