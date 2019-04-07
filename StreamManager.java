package pckg;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.ArrayList;

/**
 * Manages the in/output streams for each endpoint connection
 */
public class StreamManager {
    private ObjectOutputStream out, msgHistory;
    private ObjectInputStream in;
    private ByteArrayOutputStream byteArrOS;

    /**
     * Constructor
     *
     * @param socket
     * @throws IOException
     */
    StreamManager(Socket socket) throws IOException {
        //get and wrap client's input and output stream w/Object stream
        out = new ObjectOutputStream(socket.getOutputStream());
        in = new ObjectInputStream(socket.getInputStream());

        //Byte stream to keep track of messages received and sent
        byteArrOS = new ByteArrayOutputStream();
        msgHistory = new ObjectOutputStream(byteArrOS);
    }

    /**
     * Read objects from input stream and return them as an arraylist
     *
     * @return
     * @throws IOException
     * @throws ClassNotFoundException
     */
    public ArrayList<Object> readInputStream() throws IOException, ClassNotFoundException {
        ArrayList<Object> ret = new ArrayList();
        Object temp;
        while ((temp = in.readObject()) != null) {
            ret.add(temp);
        }

        return ret;
    }

    /**
     * Writes objects to the output stream
     *
     * @throws IOException
     */
    public void writeToStream(Object... objects) throws IOException {
        for (Object o : objects) {
            out.writeObject(o);
        }
        out.writeObject(null);
    }

    public void writeToHistory(Object ... objects) throws IOException{
        for (Object o : objects) {
            msgHistory.writeObject(o);
        }
    }

    /**
     * Writes objects to the output stream and stores the message to an byte stream
     *
     * @throws IOException
     */
    public void writeAndStore(Object... objects) throws IOException {
        writeToStream(objects);
        writeToHistory(objects);
    }

    /**
     * Closes the appropriate connections when there's an verification error
     *
     * @param socket
     * @param msg
     * @throws IOException
     */
    public void errorClose(Socket socket, String msg) throws IOException {
        System.out.print("Unable to verify certificate/signature");
        out.close();
        in.close();
        socket.close();
    }

    public byte[] getMsgHistory() {
        return byteArrOS.toByteArray();
    }
}

