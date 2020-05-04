import pandas as pd
from scipy.stats import entropy
from os import listdir
import pefile

input_original = "./appcmd.exe"
input_upx = "./appcmd_upx.exe"
input_list = [input_original, input_upx]

system32_original = "./system32_original/"
system32_upx_packed = "./system32_upx_packed/"
filelist = listdir(system32_upx_packed)

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

def create_comparisonal_graphOfAppcmd() :
    for filename in input_list :
        df = getByteDataFrameWithFilename(filename)
        entropy_df = df.rolling(window=256).apply(lambda arr : cal_entropy_with_considerNullPadding(arr))
        entropy_df_withConsideringNullPadding = entropy_df[entropy_df != -1]
        plot = entropy_df_withConsideringNullPadding.plot()
        plot.get_figure().savefig(makeOutputName(prefix="result_", filename=filename))

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

def get_entropy_distributionOfSystem32() :
    original_file_list = [system32_original+i for i in filelist]
    upx_packed_file_list = [system32_upx_packed+i for i in filelist]

    df_list_of_original = [getByteDataFrameWithFilename(i) for i in original_file_list]
    df_list_of_upx = [getByteDataFrameWithFilename(i) for i in upx_packed_file_list]

    origin_mean = [get_entropyMeanDf_with_df(i) for i in df_list_of_original]
    origin_max = [get_entropyMaxDf_with_df(i) for i in df_list_of_original]
    origin_99Percentile = [get_entropy99Percentile_with_df(i) for i in df_list_of_original]
    origin_median = [get_entropyMedianDf_with_df(i) for i in df_list_of_original]
    origin_std = [get_entropyStdDf_with_df(i) for i in df_list_of_original]
    upx_mean = [get_entropyMeanDf_with_df(i) for i in df_list_of_upx]
    upx_max = [get_entropyMaxDf_with_df(i) for i in df_list_of_upx]
    upx_99Percentile = [get_entropy99Percentile_with_df(i) for i in df_list_of_upx]
    upx_median = [get_entropyMedianDf_with_df(i) for i in df_list_of_upx]
    upx_std = [get_entropyStdDf_with_df(i) for i in df_list_of_upx]

    statics_origin = pd.DataFrame({"mean":origin_mean, "max" : origin_max, "99Percentile" : origin_99Percentile, "median" : origin_median, "std" : origin_std})
    statics_upx = pd.DataFrame({"mean":upx_mean, "max" : upx_max, "99Percentile" : upx_99Percentile, "median" : upx_median, "std" : upx_std})

    statics_origin.to_csv("./statics_origin_section.csv")
    statics_upx.to_csv("./statics_upx_section.csv")

def main() :
    #create_comparisonal_graphOfAppcmd()
    get_entropy_distributionOfSystem32()


main()
