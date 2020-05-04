import pandas as pd
from scipy.stats import entropy
from scipy.stats import norm
import matplotlib.pyplot as plt
import math
import pefile
from os import listdir
fig = plt.figure()

system32_original_statistics_df = "./statics_origin_section.csv"
system32_upx_packed_statistics_df = "./statics_upx_section.csv"

originalSample = "./originalSample/"
upxSample = "./upxSample/"
sampleList = listdir(upxSample)
statistics_df = pd.read_csv(system32_upx_packed_statistics_df)

graph_result_path = "./result_graph/"

def getByteDataFrameWithFilename(filename) :
    pe = pefile.PE(filename)
    sectionContents = ""
    for i in range(2) :
        sectionContents = pe.sections[i].get_data()
    byte_list = [int(i) for i in sectionContents]
    df = pd.DataFrame({"byte" : byte_list})
    return df

def makeOutputName(prefix, filename) :
    if "/" in filename :
        return graph_result_path+prefix+filename.split(".")[1].split("/")[-1]+".png"
    else :
        return graph_result_path+prefix+filename.split(".")[1]+".png"

def cal_entropy_with_considerNullPadding(arr) :
    count_of_zero = arr.tolist().count(0)
    if count_of_zero > len(arr)/2 :
        return -1
    else :
        return entropy(arr)

def get_entropyMeanDf_with_df (df) :
    entropy_df = df.rolling(window=256).apply(lambda arr : cal_entropy_with_considerNullPadding(arr))
    mean = entropy_df[entropy_df != -1].mean()
    return mean.values[0]

def get_entropyMaxDf_with_df (df) :
    entropy_df = df.rolling(window=256).apply(lambda arr : cal_entropy_with_considerNullPadding(arr))
    max = entropy_df[entropy_df != -1].max()
    return max.values[0]


def get_entropy99Percentile_with_df (df) :
    entropy_df = df.rolling(window=256).apply(lambda arr : cal_entropy_with_considerNullPadding(arr))
    max = entropy_df[entropy_df != -1].quantile(0.99)
    return max.values[0]

def get_entropyMedianDf_with_df (df) :
    entropy_df = df.rolling(window=256).apply(lambda arr : cal_entropy_with_considerNullPadding(arr))
    max = entropy_df[entropy_df != -1].median()
    return max.values[0]

def get_entropyStdDf_with_df (df) :
    entropy_df = df.rolling(window=256).apply(lambda arr : cal_entropy_with_considerNullPadding(arr))
    max = entropy_df[entropy_df != -1].std()
    return max.values[0]

def create_comparisonal_graphOfAppcmd() :
    for filename in input_list :
        df = getByteDataFrameWithFilename(filename)
        entropy_df = df.rolling(window=256).apply(lambda arr : cal_entropy_with_considerNullPadding(arr))
        entropy_df_withConsideringNullPadding = entropy_df[entropy_df != -1]
        plot = entropy_df_withConsideringNullPadding.plot()
        plot.get_figure().savefig(makeOutputName(prefix="result_", filename=filename))

def get_upx_mahalanobisDistance_withFilename(filename) :
    df = getByteDataFrameWithFilename(filename)

    input_median = [get_entropyMedianDf_with_df(df)]
    input_std = [get_entropyStdDf_with_df(df)]
    input_df = pd.DataFrame({"median" : input_median, "std" : input_std})

    mean = statistics_df[["median", "std"]].mean()
    std = statistics_df[["median", "std"]].std()

    normal_df = (input_df-mean)/std

    vector = normal_df.values
    distance = math.sqrt(vector[0][0]**2 + vector[0][1]**2)
    print(distance)
    print(norm.cdf(distance))
    return distance

def getSampleDf(dirPath) :
    sizeList = []
    fileList = [dirPath + fn for fn in sampleList]

    for fn in fileList :
        with open(fn, mode="rb+") as f :
            fileContents = f.read()
            sizeList.append(len(fileContents))

    reli_df = [get_upx_mahalanobisDistance_withFilename(fn) for fn in fileList]

    df = pd.DataFrame({"percentage" : reli_df, "size" : sizeList})
    return df

def main() :
#   upx_df = getSampleDf(upxSample)
#   upx_df.to_csv("comp_upx.csv")
#   origin_df = getSampleDf(originalSample)
#   origin_df.to_csv("comp_origin.csv")
    get_upx_mahalanobisDistance_withFilename("./appcmd.exe")
    get_upx_mahalanobisDistance_withFilename("./appcmd_upx.exe")




def get_entropy_scatter_graph() :

    df_of_original = getByteDataFrameWithFilename(input_original)
    df_of_upx = getByteDataFrameWithFilename(input_upx)

    origin_mean = [get_entropyMeanDf_with_df(df_of_original)]
    origin_max = [get_entropyMaxDf_with_df(df_of_original)]
    origin_99Percentile = [get_entropy99Percentile_with_df(df_of_original)]
    origin_median = [get_entropyMedianDf_with_df(df_of_original)]
    origin_std = [get_entropyStdDf_with_df(df_of_original)]
    upx_mean = [get_entropyMeanDf_with_df(df_of_original)]
    upx_max = [get_entropyMaxDf_with_df(df_of_upx)]
    upx_99Percentile = [get_entropy99Percentile_with_df(df_of_upx)]
    upx_median = [get_entropyMedianDf_with_df(df_of_upx)]
    upx_std = [get_entropyStdDf_with_df(df_of_upx)]

    statics_appcmd_origin = pd.DataFrame({"mean":origin_mean, "max" : origin_max, "99Percentile" : origin_99Percentile, "median" : origin_median, "std" : origin_std})
    statics_appcmd_upx = pd.DataFrame({"mean":upx_mean, "max" : upx_max, "99Percentile" : upx_99Percentile, "median" : upx_median, "std" : upx_std})

    origin_distribution = pd.read_csv("./statics_origin_section.csv")
    upx_distribution = pd.read_csv("./statics_upx_section.csv")

    plot = origin_distribution.plot(kind="scatter", x="median", y="std")
    plot2 = upx_distribution.plot(kind="scatter", x="median", y="std",c="b", ax=plot)
    plot3 = statics_appcmd_origin.plot(kind="scatter", x="median", y="std",c="g", ax=plot2)
    plot3.annotate("appcmd.exe", xy=(statics_appcmd_origin["median"], statics_appcmd_origin["std"]))
    plot4 = statics_appcmd_upx.plot(kind="scatter", x="median", y="std",c="r", ax=plot3)
    plot4.annotate("appcmd_upx.exe", xy=(statics_appcmd_upx["median"], statics_appcmd_upx["std"]))
    plot4.get_figure().savefig("./result_medianstd_section.png")



main()
