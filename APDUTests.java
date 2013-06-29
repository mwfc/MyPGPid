package MyPGPid;

import org.junit.*;
import static org.junit.Assert.*;
import javacard.framework.*;
import com.licel.jcardsim.base.*;
import javax.smartcardio.*;


public class APDUTests {

	private Simulator simulator;
	private AID appletAID;
	private byte[] appletAIDBytes = new byte[]{ (byte) 0xD2, 0x76, 0x00, 0x01, 0x24, 0x02, 0x00, (byte) 0xCA, (byte) 0xFE, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00};

    final static byte[] PW1_DEFAULT = {(byte)0x31, (byte)0x32, (byte)0x33, (byte)0x34, (byte)0x35, (byte)0x36 };
    final static byte[] PW3_DEFAULT = {(byte)0x31, (byte)0x32, (byte)0x33, (byte)0x34, (byte)0x35, (byte)0x36, (byte)0x37, (byte)0x38 };
    final static byte[] WRONGPIN = {(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF, (byte) 0xCA, (byte) 0xFE, (byte) 0xC0, (byte) 0xFF, (byte) 0xEE};

	@Before
	public void buildApplet() {
		simulator = new Simulator();

		appletAID = new AID(appletAIDBytes, (short) 0, (byte) appletAIDBytes.length);
		simulator.installApplet(appletAID, MyPGPid.class);
		simulator.selectApplet(appletAID);
	}

	@After
	public void destroyApplet(){
		simulator.reset();
	}
	
	@Test
	public void passwordLock(){
		ResponseAPDU response;	
		
		// verify correct PIN, resets the tries counter
		// PW1 is set to default 0x81
		response = simulator.transmitCommand(new CommandAPDU(0x00, 0x20, 0x00, 0x81, PW1_DEFAULT));
		assertEquals(0x9000, response.getSW());	
		
		for(int i = 0; i<3;i++){
			response = simulator.transmitCommand(new CommandAPDU(0x00, 0x20, 0x00, 0x81, WRONGPIN));
			assertEquals(0x6982, response.getSW());	
		}
		
		// Test whether it is blocked for correct and false PIN
		response = simulator.transmitCommand(new CommandAPDU(0x00, 0x20, 0x00, 0x81, PW1_DEFAULT));
		assertEquals(0x6983, response.getSW());		
		
		response = simulator.transmitCommand(new CommandAPDU(0x00, 0x20, 0x00, 0x81, WRONGPIN));
		assertEquals(0x6983, response.getSW());	
	}
	
	@Test
	public void passwordVerify(){
		ResponseAPDU response;
		
		// verify correct PINs
		// PW1 is set to default 0x81
		response = simulator.transmitCommand(new CommandAPDU(0x00, 0x20, 0x00, 0x81, PW1_DEFAULT));
		assertEquals(0x9000, response.getSW());	
		
		// PW1 is set to default 0x82
		response = simulator.transmitCommand(new CommandAPDU(0x00, 0x20, 0x00, 0x82, PW1_DEFAULT));
		assertEquals(0x9000, response.getSW());	
		
		// PW3 is set to default 0x83
		response = simulator.transmitCommand(new CommandAPDU(0x00, 0x20, 0x00, 0x83, PW3_DEFAULT));
		assertEquals(0x9000, response.getSW());	
		
		// verify false PINs
		// PW1 is set to default 0x81
		response = simulator.transmitCommand(new CommandAPDU(0x00, 0x20, 0x00, 0x81, WRONGPIN));
		assertEquals(0x6982, response.getSW());	
		
		// PW1 is set to default 0x82
		response = simulator.transmitCommand(new CommandAPDU(0x00, 0x20, 0x00, 0x82, WRONGPIN));
		assertEquals(0x6982, response.getSW());	
		
		// PW3 is set to default 0x83
		response = simulator.transmitCommand(new CommandAPDU(0x00, 0x20, 0x00, 0x83, WRONGPIN));
		assertEquals(0x6982, response.getSW());	
	}
	
	@Test
	public void passwordChange(){
		ResponseAPDU response;
		
		// PW1 fail
		byte[] wrongPINcorrectPIN = new byte[WRONGPIN.length + PW1_DEFAULT.length];
		System.arraycopy(WRONGPIN, 0, wrongPINcorrectPIN, 0, WRONGPIN.length);
		System.arraycopy(PW1_DEFAULT, 0, wrongPINcorrectPIN, WRONGPIN.length, PW1_DEFAULT.length);
		
		response = simulator.transmitCommand(new CommandAPDU(0x00, 0x24, 0x00, 0x81, wrongPINcorrectPIN));
		assertEquals(0x6982, response.getSW());
		
		// PW1 correct, too short
		byte[] correctPINwrongPIN = new byte[4 + PW1_DEFAULT.length];
		System.arraycopy(PW1_DEFAULT, 0, correctPINwrongPIN, 0, PW1_DEFAULT.length);
		System.arraycopy(WRONGPIN, 0, correctPINwrongPIN, PW1_DEFAULT.length, 4);
		
		response = simulator.transmitCommand(new CommandAPDU(0x00, 0x24, 0x00, 0x81, correctPINwrongPIN));
		assertEquals(0x6985, response.getSW());
		
		// PW1 correct, All good
		correctPINwrongPIN = new byte[WRONGPIN.length+ PW1_DEFAULT.length];
		System.arraycopy(PW1_DEFAULT, 0, correctPINwrongPIN, 0, PW1_DEFAULT.length);
		System.arraycopy(WRONGPIN, 0, correctPINwrongPIN, PW1_DEFAULT.length, WRONGPIN.length);
		
		response = simulator.transmitCommand(new CommandAPDU(0x00, 0x24, 0x00, 0x81, correctPINwrongPIN));
		assertEquals(0x9000, response.getSW());
		
		// PW1 fail
		wrongPINcorrectPIN = new byte[WRONGPIN.length + PW3_DEFAULT.length];
		System.arraycopy(WRONGPIN, 0, wrongPINcorrectPIN, 0, WRONGPIN.length);
		System.arraycopy(PW3_DEFAULT, 0, wrongPINcorrectPIN, WRONGPIN.length, PW3_DEFAULT.length);
		
		response = simulator.transmitCommand(new CommandAPDU(0x00, 0x24, 0x00, 0x83, wrongPINcorrectPIN));
		assertEquals(0x6982, response.getSW());
		
		// PW1 correct, too short
		correctPINwrongPIN = new byte[4 + PW3_DEFAULT.length];
		System.arraycopy(PW3_DEFAULT, 0, correctPINwrongPIN, 0, PW3_DEFAULT.length);
		System.arraycopy(WRONGPIN, 0, correctPINwrongPIN, PW3_DEFAULT.length, 4);
		
		response = simulator.transmitCommand(new CommandAPDU(0x00, 0x24, 0x00, 0x83, correctPINwrongPIN));
		assertEquals(0x6985, response.getSW());
		
		// PW1 correct, All good
		correctPINwrongPIN = new byte[WRONGPIN.length+ PW3_DEFAULT.length];
		System.arraycopy(PW3_DEFAULT, 0, correctPINwrongPIN, 0, PW3_DEFAULT.length);
		System.arraycopy(WRONGPIN, 0, correctPINwrongPIN, PW3_DEFAULT.length, WRONGPIN.length);
		
		response = simulator.transmitCommand(new CommandAPDU(0x00, 0x24, 0x00, 0x83, correctPINwrongPIN));
		assertEquals(0x9000, response.getSW());
	}
	
	@Test
	public void passwordCLA(){
		ResponseAPDU response;
		
		// verify correct PW1 against all CLAs 0x00 0x0C 0x10 0x1C 
		// CLA 0x00 and 0x0C should work
		response = simulator.transmitCommand(new CommandAPDU(0x00, 0x20, 0x00, 0x81, PW1_DEFAULT));
		assertEquals(0x9000, response.getSW());	
		response = simulator.transmitCommand(new CommandAPDU(0x0C, 0x20, 0x00, 0x81, PW1_DEFAULT));
		assertEquals(0x9000, response.getSW());
		
		// CLA 0x10 and 0x1C should fail
		response = simulator.transmitCommand(new CommandAPDU(0x10, 0x20, 0x00, 0x81, PW1_DEFAULT));
		assertEquals(0x6E00, response.getSW());	
		response = simulator.transmitCommand(new CommandAPDU(0x1C, 0x20, 0x00, 0x81, PW1_DEFAULT));
		assertEquals(0x6E00, response.getSW());		
	}
	
	@Test
	public void allCLA(){

		fail();
	}
}