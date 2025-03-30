package exifremover

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
)

// Config specifies which EXIF properties to remove
type Config struct {
	RemoveCameraInfo      bool
	RemoveGPSInfo         bool
	RemoveCopyright       bool
	RemoveDateTime        bool
	RemoveUserInfo        bool
	RemoveTechnicalDetail bool
}

// RemoveEXIFSelective removes specific EXIF properties from various image formats
func RemoveEXIFSelective(inputPath, outputPath string, config Config) error {
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer inputFile.Close()

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	// Determine file format based on signature
	header := make([]byte, 12) // Enough to identify most formats
	_, err = inputFile.Read(header)
	if err != nil {
		return err
	}
	_, err = inputFile.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	switch {
	case bytes.HasPrefix(header, []byte{0xFF, 0xD8}): // JPEG
		return processJPEG(inputFile, outputFile, config)
	case bytes.HasPrefix(header, []byte{0x89, 0x50, 0x4E, 0x47}): // PNG
		return processPNG(inputFile, outputFile, config)

	default:
		return errors.New("unsupported image format")
	}
}

// processJPEG handles JPEG files
func processJPEG(r io.Reader, w io.Writer, config Config) error {
	var output bytes.Buffer
	header := make([]byte, 2)
	if _, err := r.Read(header); err != nil {
		return err
	}
	output.Write(header)

	for {
		_, err := r.Read(header)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		if header[0] == 0xFF && header[1] == 0xE1 {
			lengthBytes := make([]byte, 2)
			if _, err := r.Read(lengthBytes); err != nil {
				return err
			}
			length := int(binary.BigEndian.Uint16(lengthBytes))
			exifData := make([]byte, length-2)
			if _, err := io.ReadFull(r, exifData); err != nil {
				return err
			}

			modifiedExif, err := modifyEXIF(exifData, config)
			if err != nil {
				return err
			}
			output.Write(header)
			binary.BigEndian.PutUint16(lengthBytes, uint16(len(modifiedExif)+2))
			output.Write(lengthBytes)
			output.Write(modifiedExif)
			continue
		}

		output.Write(header)
		if header[0] == 0xFF && header[1] == 0xDA {
			if _, err := io.Copy(&output, r); err != nil {
				return err
			}
			break
		}

		lengthBytes := make([]byte, 2)
		if _, err := r.Read(lengthBytes); err != nil {
			return err
		}
		length := int(binary.BigEndian.Uint16(lengthBytes))
		output.Write(lengthBytes)
		data := make([]byte, length-2)
		if _, err := io.ReadFull(r, data); err != nil {
			return err
		}
		output.Write(data)
	}

	_, err := w.Write(output.Bytes())
	return err
}

// processPNG handles PNG files
func processPNG(r io.Reader, w io.Writer, config Config) error {
	var output bytes.Buffer
	_, err := io.CopyN(&output, r, 8) // PNG signature
	if err != nil {
		return err
	}

	for {
		lengthBytes := make([]byte, 4)
		_, err := r.Read(lengthBytes)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		length := int(binary.BigEndian.Uint32(lengthBytes))

		typeBytes := make([]byte, 4)
		_, err = r.Read(typeBytes)
		if err != nil {
			return err
		}

		if string(typeBytes) == "eXIf" {
			exifData := make([]byte, length)
			_, err = io.ReadFull(r, exifData)
			if err != nil {
				return err
			}
			modifiedExif, err := modifyEXIF(exifData, config)
			if err != nil {
				return err
			}
			binary.BigEndian.PutUint32(lengthBytes, uint32(len(modifiedExif)))
			output.Write(lengthBytes)
			output.Write(typeBytes)
			output.Write(modifiedExif)
			_, err = io.CopyN(&output, r, 4) // CRC
			if err != nil {
				return err
			}
			continue
		}

		output.Write(lengthBytes)
		output.Write(typeBytes)
		_, err = io.CopyN(&output, r, int64(length)+4) // Data + CRC
		if err != nil {
			return err
		}
	}

	_, err = w.Write(output.Bytes())
	return err
}

// modifyEXIF processes EXIF data (shared across formats)
func modifyEXIF(data []byte, config Config) ([]byte, error) {
	if !bytes.HasPrefix(data, []byte("Exif\x00\x00")) {
		return data, nil
	}

	var order binary.ByteOrder
	if bytes.Equal(data[6:8], []byte("II")) {
		order = binary.LittleEndian
	} else if bytes.Equal(data[6:8], []byte("MM")) {
		order = binary.BigEndian
	} else {
		return nil, errors.New("invalid byte order")
	}

	offset := int(order.Uint32(data[8:12]))
	if offset+4 > len(data) {
		return data, nil
	}

	numEntries := int(order.Uint16(data[offset : offset+2]))
	pos := offset + 2

	for i := 0; i < numEntries && pos+12 <= len(data); i++ {
		tag := order.Uint16(data[pos : pos+2])
		switch tag {
		case 0x0132, 0x9003, 0x9004: // DateTime
			if config.RemoveDateTime {
				data[pos+4] = 0
				data[pos+5] = 0
				data[pos+6] = 0
				data[pos+7] = 0
			}
		case 0x9286, 0x927c, 0x8298: // User Info
			if config.RemoveUserInfo || (config.RemoveCopyright && tag == 0x8298) {
				data[pos+4] = 0
				data[pos+5] = 0
				data[pos+6] = 0
				data[pos+7] = 0
			}
		case 0x8769: // EXIF IFD
			if err := modifyExifIFD(data, int(order.Uint32(data[pos+8:pos+12])), order, config); err != nil {
				return nil, err
			}
		case 0x8825: // GPS IFD
			if config.RemoveGPSInfo {
				data[pos+8] = 0
				data[pos+9] = 0
				data[pos+10] = 0
				data[pos+11] = 0
			}
		}
		pos += 12
	}
	return data, nil
}

// modifyExifIFD modifies EXIF IFD tags
func modifyExifIFD(data []byte, offset int, order binary.ByteOrder, config Config) error {
	if offset+2 > len(data) {
		return nil
	}

	numEntries := int(order.Uint16(data[offset : offset+2]))
	pos := offset + 2

	for i := 0; i < numEntries && pos+12 <= len(data); i++ {
		tag := order.Uint16(data[pos : pos+2])
		switch tag {
		case 0x010f, 0x0110, 0x9000, 0xa000: // Camera Info
			if config.RemoveCameraInfo {
				data[pos+4] = 0
				data[pos+5] = 0
				data[pos+6] = 0
				data[pos+7] = 0
			}
		case 0x9207, 0x9209, 0x829a, 0x829d, 0x8822, 0x9204, 0x8827, 0x9201, 0x9202, 0x9205, 0x9206, 0x920a, 0xa405: // Technical Details
			if config.RemoveTechnicalDetail {
				data[pos+4] = 0
				data[pos+5] = 0
				data[pos+6] = 0
				data[pos+7] = 0
			}
		case 0x9003, 0x9004: // DateTime in EXIF IFD
			if config.RemoveDateTime {
				data[pos+4] = 0
				data[pos+5] = 0
				data[pos+6] = 0
				data[pos+7] = 0
			}
		}
		pos += 12
	}
	return nil
}
