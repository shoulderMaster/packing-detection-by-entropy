import pandas as pd
from scipy.stats import entropy

def _getByteDataFrameWithFilename(filename) :
    fileContents = ""
    with open(filename, mode="rb+") as f :
        fileContents = f.read()
    byte_list = [int(i) for i in fileContents]
    df = pd.DataFrame({"byte" : byte_list})
    return df

def makeEntropyGraphWithFilename(filename) :
    byte_df = _getByteDataFrameWithFilename(filename)
    entropy_df = byte_df.rolling(window=256).apply(lamda nparr : entropy(nparr))
    fig = entropy_df.plot().get_figure()
    #fig.show()
    return fig

def main() :
    makeEntropyGraphWithFilename(input("enter file path to get entropy graph : ")).savefig("result_graph.png")
    
main()
