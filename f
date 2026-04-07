import javax.smartcardio.*;

public class ReadCard {
    public static void main(String[] args) throws Exception {
        TerminalFactory factory = TerminalFactory.getDefault();
        CardTerminal terminal = factory.terminals().list().get(0);

        System.out.println("Prisloni karticu...");

        terminal.waitForCardPresent(0);
        Card card = terminal.connect("*");

        System.out.println("Kartica povezana: " + card);

        CardChannel channel = card.getBasicChannel();

        // Ovo je samo primjer APDU komande (ne daje JMBG!)
        byte[] command = new byte[] {(byte)0x00, (byte)0xA4, 0x04, 0x00, 0x00};
        ResponseAPDU response = channel.transmit(new CommandAPDU(command));

        System.out.println("Response: " + response);
    }
}
