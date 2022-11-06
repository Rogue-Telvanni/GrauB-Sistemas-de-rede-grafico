import matplotlib.pyplot as plt
import matplotlib.patches as patches
import numpy as np
import pcapy as p
from scapy.all import *

from protocol import Protocol


def readfiletypeofpcap(filename, filtro):
    print("Reding file {0}", filename)
    lista = []
    file = rdpcap(filename)
    sessions = file.sessions()
    count = 1
    for session in sessions:
        if not session.lower().__contains__(filtro.lower()):
            continue

        for pacote in sessions[session]:
            try:
                value = Protocol(filtro, count, pacote.time)
                lista.append(value)
                count += 1
            except IndexError:
                pass
    return lista


def plot(sctps, udps):
    plt.style.use('_mpl-gallery')

    # plot
    fig, ax = plt.subplots()

    # make the data
    totalsctp = 0.0
    for data in sctps:
        print(*["protocol: ", data.proto, ", count: ", data.num, ", tempo: ", data.tempo])
        totalsctp += data.tempo
        ax.plot(totalsctp, data.num, 'o', color='red', picker=True)

    totaludp = 0.0
    for udp in udps:
        print(*["protocol: ", udp.proto, ", count: ", udp.num, ", tempo: ", udp.tempo])
        totaludp += udp.tempo
        ax.plot(totaludp, udp.num, 'o', color='blue', picker=True)

    plt.title('protocolos')
    red_patch = patches.Patch(color='red', label='SCTP')
    blue_patch = patches.Patch(color='blue', label='UDP')
    green_patch = patches.Patch(color='green', label='TCP')

    ax.set_xlabel("tempo(s)")
    ax.set_ylabel("pacotes")
    plt.legend(handles=[red_patch, blue_patch, green_patch])
    plt.tight_layout()
    plt.show()


if __name__ == '__main__':
    SCTPData = readfiletypeofpcap("wireSCTP.pcap", "SCTP")
    UDPData = readfiletypeofpcap("wireUDP.pcap", "UDP")
    plot(SCTPData, UDPData)
    print("conclusion")
