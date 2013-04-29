library(maps)
library(mapdata)

png(filename="IMT553-Team-LGGH/ipMap.png", width=1080, unit="px")
map(database="world", ylim=c(-60,90), col="gray90", fill=TRUE)  #plot the region of Canada I want
hits <- read.csv("IMT553-Team-LGGH/IP Latitude,Longitude - Sheet 1.csv")
points(hits$Longitude, hits$Latitude, pch=20, col="red", cex=1.5)  #plot my sample sites
dev.off()
