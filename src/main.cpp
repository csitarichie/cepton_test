/**
 * Sample code for custom packet replaying.
 */

#include "cepton_sdk_api.hpp"

#include "Packet.h"
#include "PcapFileDevice.h"
#include "IPv4Layer.h"
#include "UdpLayer.h"
#include "PayloadLayer.h"

class CaptureReplay {
public:
  CaptureReplay(const std::string& path) : m_pcapReader(path.c_str()) {
    if(m_pcapReader.open())
    {
      std::printf("SUCCESS opening %s.pcap for reading\n", path.c_str());
    }

    CEPTON_CHECK_ERROR(
        cepton_sdk_set_control_flags(CEPTON_SDK_CONTROL_DISABLE_NETWORK,
                                     CEPTON_SDK_CONTROL_DISABLE_NETWORK));
    CEPTON_CHECK_ERROR(cepton_sdk_clear());
  }

  ~CaptureReplay() {
    m_pcapReader.close();
    if (cepton_sdk_is_initialized()) {
      CEPTON_CHECK_ERROR(cepton_sdk_clear());
    }
  }

  void run() {
    pcpp::RawPacket rawPacket;
    while (m_pcapReader.getNextPacket(rawPacket)) {
      pcpp::Packet decodedPacket(&rawPacket);
      const int64_t timestamp = rawPacket.getPacketTimeStamp()
                                    .tv_sec*1000000LL  +
                                rawPacket.getPacketTimeStamp
                                    ().tv_usec;
      if(decodedPacket.isPacketOfType(pcpp::UDP))
      {

        const CeptonSensorHandle handle =
                                     decodedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIpAddress().toInt()
                                     | CEPTON_SENSOR_HANDLE_FLAG_MOCK;

        std::printf("PCAP PDU header:\n "
                    "%s",
                    decodedPacket
                        .toString().c_str());

        std::printf("CEPTON API call with data size: %d "
                    "handle:"
                    " 0x%016llx timestamp in unix:0x%016llx\n",
                    (int)decodedPacket.getLayerOfType<pcpp::UdpLayer>()->getLayerPayloadSize(),
                    handle, timestamp);

        std::printf("CEPTON API DATA pointer PDU Payload:\n");
        for(int index=0; index < 40; ++index)
        {
          std::printf("0x%02x ",
                      *(decodedPacket.getLayerOfType<pcpp::PayloadLayer>()->getData()+index));
          if( (index+1) % 10 == 0)
          {
            std::printf("\n");
          }
        }

        CEPTON_CHECK_ERROR(cepton_sdk::mock_network_receive(
            handle, timestamp,
            decodedPacket.getLayerOfType<pcpp::PayloadLayer>()->getData(),
            decodedPacket.getLayerOfType<pcpp::UdpLayer>()->getLayerPayloadSize()));

      } else {
        std::printf("Ignore Packet Non udp\n");
      }

    }

  }
private:
  pcpp::PcapFileReaderDevice  m_pcapReader;
};

int main(int argc, char** argv) {
  if (argc < 2) return -1;
  const std::string capture_path = argv[1];

  // Initialize
  auto options = cepton_sdk::create_options();
  options.control_flags |= CEPTON_SDK_CONTROL_DISABLE_NETWORK;
  options.frame.mode = CEPTON_SDK_FRAME_COVER;
  CEPTON_CHECK_ERROR(cepton_sdk::api::initialize(options));

  // Listen for points
  cepton_sdk::api::SensorImageFrameCallback callback;
  CEPTON_CHECK_ERROR(callback.initialize());
  CEPTON_CHECK_ERROR(
      callback.listen([](cepton_sdk::SensorHandle handle, std::size_t n_points,
                         const cepton_sdk::SensorImagePoint* c_image_points) {
        std::printf("Received %i points from sensor %lli\n", (int)n_points,
                    (long long)handle);
      }));

  // Run
  CaptureReplay replay(capture_path);
  replay.run();

  // Deinitialize
  cepton_sdk::deinitialize().ignore();
}
