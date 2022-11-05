import matplotlib.pyplot as plt
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
        if not session.lower().__contains__("proto=" + filtro.lower()):
            continue

        for pacote in sessions[session]:
            try:
                value = Protocol(filtro, count)
                lista.append(value)
            except IndexError:
                pass


def plot():
    plt.style.use('_mpl-gallery')

    # make data
    x = np.linspace(0, 10, 100)
    y = 4 + 2 * np.sin(2 * x)

    # plot
    fig, ax = plt.subplots()

    ax.plot(x, y, linewidth=2.0)

    ax.set(xlim=(0, 8), xticks=np.arange(1, 8),
           ylim=(0, 8), yticks=np.arange(1, 8))

    plt.show()


if __name__ == '__main__':
    readfiletypeofpcap("wireSCTP.pcap", "SCTP")
    plot()
    print("conclusion")
