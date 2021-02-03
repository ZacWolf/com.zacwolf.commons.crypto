/**
 * Copyright 2003-2016 SSHTOOLS Limited. All Rights Reserved.
 *
 * For product documentation visit https://www.sshtools.com/
 *
 * This file is part of J2SSH Maverick.
 *
 * J2SSH Maverick is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * J2SSH Maverick is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with J2SSH Maverick.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.zacwolf.commons.crypto.io;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

/**
 *
 * <p>
 * Utility class to write common parameter types to a byte array.
 * </p>
 *
 * @author Lee David Painter
 */
public class ByteArrayWriter extends ByteArrayOutputStream {

	/**
	 * Contruct an empty writer.
	 */
	public ByteArrayWriter() {

	}

	/**
	 * Construct a writer with an array size of the length supplied.
	 *
	 * @param length
	 */
	public ByteArrayWriter(final int length) {
		super(length);
	}

	/**
	 * Get the underlying byte array
	 *
	 * @return the underlying byte array.
	 */
	public byte[] array() {
		return buf;
	}

	/**
	 * Move the position of the next byte to be written.
	 *
	 * @param numBytes
	 */
	public void move(final int numBytes) {
		count += numBytes;
	}

	/**
	 * Write a BigInteger to the array.
	 *
	 * @param bi
	 * @throws IOException
	 */
	public void writeBigInteger(final BigInteger bi) throws IOException {
		final byte[] raw = bi.toByteArray();

		writeInt(raw.length);
		write(raw);
	}

	/**
	 * Write a boolean value to the array.
	 *
	 * @param b
	 * @throws IOException
	 */
	public void writeBoolean(final boolean b) {
		write(b ? 1 : 0);
	}

	/**
	 * Write a binary string to the array.
	 *
	 * @param data
	 * @throws IOException
	 */
	public void writeBinaryString(final byte[] data) throws IOException {
		if (data == null) {
			writeInt(0);
		} else {
			writeBinaryString(data, 0, data.length);
		}
	}

	/**
	 * Write a binary string to the array.
	 *
	 * @param data
	 * @param offset
	 * @param len
	 * @throws IOException
	 */
	public void writeBinaryString(final byte[] data, final int offset, final int len)
			throws IOException {
		if (data == null) {
			writeInt(0);
		} else {
			writeInt(len);
			write(data, offset, len);
		}
	}

	public void writeMPINT(final BigInteger b) {
		final short bytes = (short) ((b.bitLength() + 7) / 8);
		final byte[] raw = b.toByteArray();
		writeShort((short) b.bitLength());
		if (raw[0] == 0) {
			write(raw, 1, bytes);
		} else {
			write(raw, 0, bytes);
		}
	}

	public void writeShort(final short s) {
		write(s >>> 8 & 0xFF);
		write(s >>> 0 & 0xFF);
	}

	/**
	 * Write an integer to the array
	 *
	 * @param i
	 * @throws IOException
	 */
	public void writeInt(final long i) throws IOException {
		final byte[] raw = new byte[4];

		raw[0] = (byte) (i >> 24);
		raw[1] = (byte) (i >> 16);
		raw[2] = (byte) (i >> 8);
		raw[3] = (byte) i;

		write(raw);
	}

	/**
	 * Write an integer to the array.
	 *
	 * @param i
	 * @throws IOException
	 */
	public void writeInt(final int i) throws IOException {
		final byte[] raw = new byte[4];

		raw[0] = (byte) (i >> 24);
		raw[1] = (byte) (i >> 16);
		raw[2] = (byte) (i >> 8);
		raw[3] = (byte) i;

		write(raw);
	}

	/**
	 * Encode an integer into a 4 byte array.
	 *
	 * @param i
	 * @return a byte[4] containing the encoded integer.
	 */
	public static byte[] encodeInt(final int i) {
		final byte[] raw = new byte[4];
		raw[0] = (byte) (i >> 24);
		raw[1] = (byte) (i >> 16);
		raw[2] = (byte) (i >> 8);
		raw[3] = (byte) i;
		return raw;
	}

	public static void encodeInt(final byte[] buf, int off, final int i) {
		buf[off++] = (byte) (i >> 24);
		buf[off++] = (byte) (i >> 16);
		buf[off++] = (byte) (i >> 8);
		buf[off] = (byte) i;
	}

	/*
	 * public static void writeIntToArray(byte[] array, int pos, int value)
	 * throws IOException { if ( (array.length - pos) < 4) { throw new
	 * IOException( "Not enough data in array to write integer at position " +
	 * String.valueOf(pos)); } array[pos] = (byte) (value >> 24); array[pos + 1]
	 * = (byte) (value >> 16); array[pos + 2] = (byte) (value >> 8); array[pos +
	 * 3] = (byte) (value); }
	 */

	/**
	 * Write a string to the byte array.
	 *
	 * @param str
	 * @throws IOException
	 */
	public void writeString(final String str) throws IOException {
		writeString(str, ByteArrayReader.getCharsetEncoding());
	}

	/**
	 * Write a String to the byte array converting the bytes using the given
	 * character set.
	 *
	 * @param str
	 * @param charset
	 * @throws IOException
	 */
	public void writeString(final String str, final String charset) throws IOException {

		if (str == null) {
			writeInt(0);
		} else {
			byte[] tmp;

			if (ByteArrayReader.encode) {
				tmp = str.getBytes(charset);
			} else {
				tmp = str.getBytes();
			}

			writeInt(tmp.length);
			write(tmp);
		}
	}

	public void dispose() {
		super.buf = null;
	}

}
